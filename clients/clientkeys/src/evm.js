// EVM pieces: EIP-712 digests, addresses, SmartKeyAccount key/salt/CREATE2, Merkle batch, the typed builder of every named entry.
import {
  keccak_256, sha256, concatBytes, utf8ToBytes, bytesToHex, fromHex, hex, word, boolWord, addressWord, abiEncode, bytes32,
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

const elementType = (t) => t.replace(/\[\]$/, '');

/** EIP-712 `encodeType`: the primary type, then every struct it references, sorted by name. */
export function encodeType(types, primary) {
  const deps = new Set();
  const walk = (t) => types[t].forEach((f) => {
    const e = elementType(f.type);
    if (types[e] && e !== primary && !deps.has(e)) { deps.add(e); walk(e); }
  });
  walk(primary);
  const one = (t) => `${t}(${types[t].map((f) => `${f.type} ${f.name}`).join(',')})`;
  return [primary, ...[...deps].sort()].map(one).join('');
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
const relayFeeOf = (id) => `${id} from,address target,bytes32 callDataHash,${id} payee,uint256 value,uint256 validUntil,address relayer`;
const RECEIVER_FEE = 'uint256 fee,address feeRecipient,uint256 validUntil';

// Every struct a signed type nests or an entry takes (Appendix X.2). The last group is calldata only, never signed.
const STRUCTS = Object.fromEntries(Object.entries({
  // the order's sell side (CTR-DEX-13, CTR-DEX-25: ids as bytes32) and an outside token's `DexOrder` (CTR-DEX-18)
  TradeOrder: orderOf('address'), UATradeOrder: orderOf('bytes32'), DexOrder: 'address sellToken,TradeOrder order',
  WrapOrder: wrapOrderOf('address'), UAWrapOrder: wrapOrderOf('bytes32'),
  // the token's typed transfer and payment (CTR-MTX-23); `entryRef = 0` is a transfer, else a payment (CTR-UA-26 on ids)
  MetaTransfer: transferOf('address'), UAMetaTransfer: transferOf('bytes32'),
  PqzTransferArgs: 'uint64 p,uint256 validUntilBlock,uint256 shieldIn,bytes32 fromUA,bytes32 toUA,bytes32 beneficiaryUA,bytes16 salt,'
    + 'bytes u,bytes vTo,bytes vFrom,bytes vAuditor,bytes sealedMemo',
  PqzLeg: 'bytes32 ua,bytes v,bytes vAuditor',
  PqzMultiArgs: 'uint64 p,uint256 validUntilBlock,uint256 shieldIn,bytes32 fromUA,bytes32 beneficiaryUA,uint256 decoyFee,bytes16 salt,'
    + 'bytes[] u,PqzLeg[] legs,bytes vFrom,bytes sealedMemo',
  PqzBurnArgs: 'uint64 p,uint256 validUntilBlock,uint256 shieldIn,bytes32 fromUA,bytes32 beneficiaryUA,bytes u,bytes vFrom',
  Unwrap: 'address underlying,bytes32 recipient,uint256 amount,uint256 minOut',
  G1: 'bytes32 x0,bytes32 x1,bytes32 y0,bytes32 y1',
  ZetherSingle: 'uint64 accSeq,uint64 sendCounter,uint256 validUntilBlock,bytes16 salt,bytes32 beneficiaryUA,'
    + 'G1 yFrom,G1 yTo,G1 cOut,G1 dOut,G1 cDeb,G1 cAud',
  ZetherLeg: 'G1 yTo,G1 cOut,G1 cAud,G1 dAud',
  ZetherMulti: 'uint64 accSeq,uint64 sendCounter,uint256 validUntilBlock,bytes16 salt,bytes32 beneficiaryUA,uint256 decoyFee,'
    + 'G1 yFrom,G1 dOut,G1 cDeb,ZetherLeg[] legs,bytes sealedMemo',
  ZetherBurn: 'uint64 accSeq,uint64 sendCounter,uint256 validUntilBlock,bytes32 beneficiaryUA,G1 yFrom',
  Envelope: `address from,${E}`, UAEnvelope: `bytes32 from,${E}`, MemberSig: 'uint16 index,bytes keyData,bytes sig',
  UASig: 'bytes keyData,bytes signature,MemberSig[] members', AccountSig: 'uint256 keyIndex,bytes32[] proof,bytes signature',
  Payout: 'uint256 amount,bytes32 recipient',
}).map(([name, list]) => [name, fields(list)]));

const DOMAIN_OF = { NormalToken: 'SCaaS MetaToken', WrappedToken: 'SCaaS MetaToken', NormalZetherToken: 'SCaaS ZetherToken',
  WrappedZetherToken: 'SCaaS ZetherToken', NormalPqzToken: 'SCaaS PqzToken', WrappedPqzToken: 'SCaaS PqzToken',
  MandateWallet: 'SCaaS MandateWallet', SmartKeyAccount: 'SCaaS SmartKeyAccount', SCaaSDex: 'SCaaS Dex' };
const NORMAL = ['NormalToken', 'NormalZetherToken', 'NormalPqzToken'];
const WRAPPED = ['WrappedToken', 'WrappedZetherToken', 'WrappedPqzToken'];
const TOKENS = [...NORMAL, ...WRAPPED];
const ZETHER = ['NormalZetherToken', 'WrappedZetherToken'];
const PQZ = ['NormalPqzToken', 'WrappedPqzToken'];
const CONFIDENTIAL = [...ZETHER, ...PQZ];
const WRAPPED_CONFIDENTIAL = ['WrappedZetherToken', 'WrappedPqzToken'];
const WALLET = ['MandateWallet'];
const ACCOUNT = ['SmartKeyAccount'];

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

// The one table of the type strings (plan Part C, Appendix X.4). `fields`: the struct `<Name>(address from,<fields>,E)`
// (TS-D14), `ua`: with its twin `UA<Name>(bytes32 from,…)`, entries `mtx<Name>` / `ua<Name>`; `entry`: their name when it
// is not the struct's (TS-D16), `args`: their parameters. `raw`: a struct without `E`, with the whole `entry` and `call`.
// `on`: the contracts that take it. `amount`: the op's amount field where the fee class is AMOUNT (CTR-MTX-20).
const OPS = {
  CancelNonce: { fields: 'uint256 lane', on: [...TOKENS, ...WALLET, ...ACCOUNT] },
  Burn: { fields: 'uint256 amount', on: NORMAL, ua: true, amount: 'amount' },
  Wrap: { fields: 'uint256 amount', on: WRAPPED },
  WrapLeg: { fields: 'address underlying,uint256 amount', on: WRAPPED },
  Unwrap: { fields: 'uint256 wrapped,address recipient,uint256 minOut', on: WRAPPED, ua: true, amount: 'wrapped' },
  UnwrapLeg: { fields: 'address underlying,uint256 wrapped,address recipient,uint256 minOut', on: WRAPPED, ua: true, amount: 'wrapped' },
  AddReserve: { fields: 'address underlying,uint256 amount', on: WRAPPED },
  WrapToUA: { fields: 'address underlying,uint256 amount,bytes32 to', on: WRAPPED },
  UnwrapToUA: { fields: 'address underlying,uint256 wrapped,bytes32 to,uint256 minOut', on: WRAPPED, ua: true, amount: 'wrapped' },
  // `uaBytes`: the C0 spike's `uaShield` takes `bytes auth` until C2 moves the `ua*` entries to `UASig`.
  Shield: { fields: 'bytes32 toUA,uint256 amount', on: CONFIDENTIAL, ua: true, uaBytes: true },
  WrapShield: { fields: 'address underlying,uint256 amountIn,bytes32 toUA', on: WRAPPED_CONFIDENTIAL },
  RollOver: { fields: 'bytes32 ua,uint256 n', on: CONFIDENTIAL, ua: true },
  PrepareAcc: { fields: 'bytes32 ua,uint256 half', on: PQZ, ua: true },
  // MandateWallet: the owner's three, the delegate's two (CTR-ACC-07), the arbitrary call
  SetMandate: { fields: 'address token,address delegate,uint128 maxPerPayment,uint128 maxPerPeriod,uint64 periodSeconds,uint64 expiry', on: WALLET },
  SetPayee: { fields: 'address token,address payee,bool allowed', on: WALLET },
  RevokeMandate: { fields: 'address token', on: WALLET },
  PayUnderMandate: { fields: 'address token,address payee,uint256 amount,bytes32 entryRef,uint64 epoch', on: WALLET },
  DelegateRevoke: { fields: 'address token,uint64 epoch', on: WALLET },
  // SmartKeyAccount: `SubjectKey` flattened, its own entries signed with `AccountSig` (Appendix X row 13)
  AddKey: { fields: 'uint8 kind,bytes32 x,bytes32 y,bytes32 rpIdHash,bytes32 originHash', on: ACCOUNT, accountSig: true },
  RemoveKey: { fields: 'uint256 index', on: ACCOUNT, accountSig: true },
  RotateKey: { fields: 'uint256 index,uint8 kind,bytes32 x,bytes32 y,bytes32 rpIdHash,bytes32 originHash', on: ACCOUNT, accountSig: true },
  SetGuardian: { fields: 'address guardian', on: ACCOUNT, accountSig: true },
  CancelRecovery: { fields: '', on: ACCOUNT, accountSig: true },
  Execute: { fields: 'address target,uint256 value,bytes data', on: [...WALLET, ...ACCOUNT], accountSig: true },
  // PQZ (Appendix X.3; `Payout` as C0 found: the flat `amount, recipient` does not compile there, evm-size-levers.md §7)
  PqzTransferSingle: { fields: `PqzTransferArgs args,${PQZ_TAIL}`, on: PQZ, ua: true, entry: 'ConfidentialTransferSingle', args: pqzOp('PqzTransferArgs') },
  PqzTransferSingleCompact: { fields: `PqzTransferArgs args,${PQZ_TAIL}`, on: PQZ, ua: true, entry: 'ConfidentialTransferSingleCompact', args: pqzOp('PqzTransferArgs') },
  PqzTransfer: { fields: `PqzMultiArgs args,${PQZ_TAIL}`, on: PQZ, ua: true, entry: 'ConfidentialTransfer', args: pqzOp('PqzMultiArgs') },
  PqzTransferCompact: { fields: `PqzMultiArgs args,${PQZ_TAIL}`, on: PQZ, ua: true, entry: 'ConfidentialTransferCompact', args: pqzOp('PqzMultiArgs') },
  PqzUnshield: { fields: `PqzBurnArgs args,uint256 amount,bytes32 recipient,${PQZ_TAIL}`, on: PQZ, ua: true, entry: 'Unshield', args: pqzUnshield },
  PqzUnshieldUnwrap: { fields: `PqzBurnArgs args,Unwrap unwrap,${PQZ_TAIL}`, on: ['WrappedPqzToken'], ua: true, entry: 'UnshieldUnwrap', args: pqzUnwrap },
  // Zether (Appendix X.3)
  ZetherTransferSingle: { fields: 'ZetherSingle args,bytes proof', on: ZETHER, ua: true, entry: 'ConfidentialTransferSingle', args: zetherOp('ZetherSingle') },
  ZetherTransfer: { fields: 'ZetherMulti args,bytes proof', on: ZETHER, ua: true, entry: 'ConfidentialTransfer', args: zetherOp('ZetherMulti') },
  ZetherTransferCompact: { fields: 'ZetherMulti args,bytes proof', on: ZETHER, ua: true, entry: 'ConfidentialTransferCompact', args: zetherOp('ZetherMulti') },
  ZetherUnshield: { fields: 'ZetherBurn args,uint256 amount,bytes32 recipient,bytes proof', on: ZETHER, ua: true, entry: 'Unshield',
    args: (m) => [['ZetherBurn', m.args], ['uint256', m.amount], ['bytes32', m.recipient], ['bytes', m.proof]] },
  ZetherUnshieldUnwrap: { fields: 'ZetherBurn args,Unwrap unwrap,bytes proof', on: ['WrappedZetherToken'], ua: true, entry: 'UnshieldUnwrap',
    args: (m) => [['ZetherBurn', m.args], ['Unwrap', m.unwrap], ['bytes', m.proof]] },
  RollOverSigned: { fields: 'bytes32 ua,uint64 expectedPendingSeq,uint64 validUntilBlock', on: ZETHER, ua: true,
    args: (m, x) => [['bytes32', m.ua], ['uint64', m.expectedPendingSeq], ['uint64', m.validUntilBlock], ['UASig', uaSigOf(x.ownerSig, 'ownerSig')]] },
  SetRollOverMode: { fields: 'bytes32 ua,uint8 rollOverMode,uint64 validUntilBlock', on: ZETHER, ua: true,
    args: (m, x) => [['bytes32', m.ua], ['uint8', m.rollOverMode], ['uint64', m.validUntilBlock], ['UASig', uaSigOf(x.ownerSig, 'ownerSig')]] },
  RollOverBatch: { fields: 'bytes32[] uas', on: ZETHER, ua: true },
  // TS-D19: `x.payerSig` is the payer's signature of the nested payment (the plain `MetaTransfer` / `UAMetaTransfer`)
  ReceiverFee: { raw: `MetaTransfer payment,${RECEIVER_FEE}`, on: TOKENS, entry: 'mtxPayReceiverFee', call: (m, sig, x) => [['MetaTransfer', m.payment],
    ['bytes', required(x.payerSig, 'payerSig')], ['uint256', m.fee], ['address', m.feeRecipient], ['uint256', m.validUntil], ['bytes', sig]] },
  UAReceiverFee: { raw: `UAMetaTransfer payment,${RECEIVER_FEE}`, on: TOKENS, entry: 'uaPayReceiverFee', call: (m, sig, x) => [['UAMetaTransfer', m.payment],
    ['UASig', uaSigOf(x.payerSig, 'payerSig')], ['uint256', m.fee], ['address', m.feeRecipient], ['uint256', m.validUntil], ['UASig', uaSigOf(sig)]] },
  // The router calls these as the struct's `relayer` (`msg.sender`), on the lane `payLane(ref)`, nonce 0.
  RelayFee: { raw: relayFeeOf('address'), on: TOKENS, entry: 'mtxRelayFee', call: (m, sig) => [['address', m.from], ['address', m.target],
    ['bytes32', m.callDataHash], ['address', m.payee], ['uint256', m.value], ['uint256', m.validUntil], ['bytes', sig]] },
  UARelayFee: { raw: relayFeeOf('bytes32'), on: TOKENS, entry: 'uaRelayFee', call: (m, sig) => [['bytes32', m.from], ['address', m.target],
    ['bytes32', m.callDataHash], ['bytes32', m.payee], ['uint256', m.value], ['uint256', m.validUntil], ['UASig', uaSigOf(sig)]] },
  // Signed in the underlying's domain, submitted to `wrappedToken`, which needs the leg: `underlying` is `verifyingContract`.
  WrapOrder: { raw: wrapOrderOf('address'), on: TOKENS, entry: 'mtxWrapOrder',
    call: (m, sig, x, td) => [['address', td.domain.verifyingContract], ['WrapOrder', m], ['bytes', sig]] },
  UAWrapOrder: { raw: wrapOrderOf('bytes32'), on: TOKENS, entry: 'uaWrapOrder',
    call: (m, sig, x, td) => [['address', td.domain.verifyingContract], ['UAWrapOrder', m], ['UASig', uaSigOf(sig)]] },
  // The cancel nests the struct the order was signed in; a wrap order goes through the same entries as the order form.
  CancelOrder: { raw: 'TradeOrder order', on: TOKENS, entry: 'mtxCancelOrder', call: (m, sig) => [['TradeOrder', m.order], ['bytes', sig]] },
  CancelUAOrder: { raw: 'UATradeOrder order', on: TOKENS, entry: 'uaCancelOrder', call: (m, sig) => [['UATradeOrder', m.order], ['UASig', uaSigOf(sig)]] },
  CancelWrapOrder: { raw: 'WrapOrder order', on: TOKENS, entry: 'mtxCancelOrder',
    call: (m, sig) => [['TradeOrder', asTradeOrder(m.order)], ['bytes', sig]] },
  CancelUAWrapOrder: { raw: 'UAWrapOrder order', on: TOKENS, entry: 'uaCancelOrder',
    call: (m, sig) => [['UATradeOrder', asTradeOrder(m.order)], ['UASig', uaSigOf(sig)]] },
  CancelDexOrder: { raw: 'DexOrder order', on: ['SCaaSDex'], entry: 'mtxCancelOrders', call: (m, sig) => [['DexOrder[]', [m.order]], ['bytes[]', [sig]]] },
  UACancelNonce: { raw: 'bytes32 ua,uint256 batch,uint256 validUntil', on: TOKENS, entry: 'uaCancelNonce',
    call: (m, sig) => [['bytes32', m.ua], ['uint256', m.batch], ['uint256', m.validUntil], ['UASig', uaSigOf(sig)]] },
  // The owner's own signature (purpose `zether-owner`), `ownerSig` of the direct ops and of `RollOverSigned` / `SetRollOverMode`.
  ZetherRollOver: { raw: 'bytes32 ua,uint64 accSeq,uint64 expectedPendingSeq,uint64 validUntilBlock', on: ZETHER, entry: 'mtxRollOverSigned',
    call: (m, sig) => [['bytes32', m.ua], ['uint64', m.expectedPendingSeq], ['uint64', m.validUntilBlock], ['UASig', uaSigOf(sig)]] },
  ZetherSetRollOverMode: { raw: 'bytes32 ua,uint8 mode,uint64 modeNonce,uint64 validUntilBlock', on: ZETHER, entry: 'mtxSetRollOverMode',
    call: (m, sig) => [['bytes32', m.ua], ['uint8', m.mode], ['uint64', m.validUntilBlock], ['UASig', uaSigOf(sig)]] },
  // The statement's header words verbatim (purpose `zether-auth`); signed into `pqzAuth`, no entry of its own.
  PqzAuth: { raw: 'uint8 op,bytes32 opTag,bytes32 psid,uint256 chainId,address token,address registry,bytes32 from,bytes32 to,bytes32 beneficiary,'
    + 'uint256 fee,uint256 amount,bytes32 recipient,uint64 sendCounter,uint64 p,uint256 validUntilBlock,bool auditorOn,uint256 shieldIn,'
    + 'bytes32 chainUid,bytes32 binding,uint128 salt,bytes32 memoHash,bytes32 bodyHash', on: PQZ },
};

const abiType = (t) => {
  if (t.endsWith('[]')) return `${abiType(elementType(t))}[]`;
  return STRUCTS[t] ? `(${STRUCTS[t].map((f) => abiType(f.type)).join(',')})` : t;
};
const abiValue = (t, v) => {
  if (t.endsWith('[]')) return v.map((x) => abiValue(elementType(t), x));
  return STRUCTS[t] ? STRUCTS[t].map((f) => abiValue(f.type, v[f.name])) : v;
};

/** One signed struct (twin `ua`): its type string and typehash, and `call(td, sig, extra)` → the entry's `{abi, data}`. */
function defineOp(primary, def, ua) {
  const own = fields(def.raw ?? [`${ua ? 'bytes32' : 'address'} from`, def.fields, E].filter(Boolean).join(','));
  const types = { EIP712Domain: SALTED_DOMAIN_TYPE, [primary]: own };
  const nest = (list) => list.forEach((f) => {
    const t = elementType(f.type);
    if (STRUCTS[t] && !types[t]) { types[t] = STRUCTS[t]; nest(STRUCTS[t]); }
  });
  nest(own);
  const typeString = encodeType(types, primary);
  const base = primary.replace(/^UA/, '');
  const entry = def.raw ? def.entry : `${ua ? 'ua' : 'mtx'}${def.entry ?? base}`;
  const sigParam = (td, sig) => {
    if (ua) return def.uaBytes ? ['bytes', sig] : ['UASig', uaSigOf(sig)];
    return def.accountSig && td.domain.name === DOMAIN_OF.SmartKeyAccount ? ['AccountSig', accountSigOf(sig)] : ['bytes', sig];
  };
  const call = (td, sig, x = {}) => {
    const m = td.message;
    const params = def.raw ? def.call(m, sig, x, td) : [[ua ? 'UAEnvelope' : 'Envelope', m],
      ...(def.args ? def.args(m, x) : own.slice(1, -7).map((f) => [f.type, m[f.name]])), sigParam(td, sig)];
    const abiTypes = params.map(([t]) => abiType(t));
    const abi = `${entry}(${abiTypes.join(',')})`;
    return { abi, data: abiCall(abi, abiTypes, params.map(([t, v]) => abiValue(t, v))) };
  };
  return { primary, typeString, typehash: hex(keccak_256(utf8ToBytes(typeString))), types, fields: own, on: def.on, ua,
    envelope: !def.raw, amount: def.amount, entry, domains: [...new Set(def.on.map((c) => DOMAIN_OF[c]))], call: entry ? call : null };
}

/** Every signed struct by name: {typeString, typehash, types, fields, on, entry, domains, call}. */
export const TYPED_OPS = Object.freeze(Object.fromEntries(Object.entries(OPS).flatMap(([name, def]) => [[name, defineOp(name, def, false)],
  ...(def.ua ? [[`UA${name}`, defineOp(`UA${name}`, def, true)]] : [])])));

/** The canonical JSON a wallet signs: unset fields 0, hex bytes, uint ≤ 32 bits as numbers, the others as decimal
 *  strings; `relayer` / `feeRecipient` canonical-zeroed as the contract hashes them (`MetaTxLib.canon`), nested `MetaTransfer` too. */
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

const opName = (primary) => primary.replace(/^UA/, 'ua').replace(/^[A-Z]/, (c) => c.toLowerCase());
/** `<op>TypedData({name, contract, chainId, chainUid, message})` and `<op>Calldata(td, sig, extra)` of every struct
 *  (`extra`: `pqzAuth`, `ownerSig`, `payerSig` where the entry takes one); exported by name below and from zether.js. */
export const OP_BUILDERS = Object.freeze(Object.fromEntries(Object.values(TYPED_OPS).flatMap((op) => [
  [`${opName(op.primary)}TypedData`, (o) => opTypedData(op, o)],
  ...(op.call ? [[`${opName(op.primary)}Calldata`, (td, sig, x) => op.call(td, sig, x).data]] : [])])));
export const {
  cancelNonceTypedData, cancelNonceCalldata, burnTypedData, burnCalldata, uaBurnTypedData, uaBurnCalldata,
  wrapTypedData, wrapCalldata, wrapLegTypedData, wrapLegCalldata, unwrapTypedData, unwrapCalldata, uaUnwrapTypedData, uaUnwrapCalldata,
  unwrapLegTypedData, unwrapLegCalldata, uaUnwrapLegTypedData, uaUnwrapLegCalldata, addReserveTypedData, addReserveCalldata,
  wrapToUATypedData, wrapToUACalldata, unwrapToUATypedData, unwrapToUACalldata, uaUnwrapToUATypedData, uaUnwrapToUACalldata,
  shieldTypedData, shieldCalldata, uaShieldTypedData, uaShieldCalldata, wrapShieldTypedData, wrapShieldCalldata,
  rollOverTypedData, rollOverCalldata, uaRollOverTypedData, uaRollOverCalldata,
  prepareAccTypedData, prepareAccCalldata, uaPrepareAccTypedData, uaPrepareAccCalldata,
  setMandateTypedData, setMandateCalldata, setPayeeTypedData, setPayeeCalldata, revokeMandateTypedData, revokeMandateCalldata,
  payUnderMandateTypedData, payUnderMandateCalldata, delegateRevokeTypedData, delegateRevokeCalldata,
  addKeyTypedData, addKeyCalldata, removeKeyTypedData, removeKeyCalldata, rotateKeyTypedData, rotateKeyCalldata,
  setGuardianTypedData, setGuardianCalldata, cancelRecoveryTypedData, cancelRecoveryCalldata, executeTypedData, executeCalldata,
  receiverFeeTypedData, receiverFeeCalldata, uaReceiverFeeTypedData, uaReceiverFeeCalldata,
  relayFeeTypedData, relayFeeCalldata, uaRelayFeeTypedData, uaRelayFeeCalldata,
  wrapOrderTypedData, wrapOrderCalldata, uaWrapOrderTypedData, uaWrapOrderCalldata,
  cancelOrderTypedData, cancelOrderCalldata, cancelUAOrderTypedData, cancelUAOrderCalldata,
  cancelWrapOrderTypedData, cancelWrapOrderCalldata, cancelUAWrapOrderTypedData, cancelUAWrapOrderCalldata,
  cancelDexOrderTypedData, cancelDexOrderCalldata, uaCancelNonceTypedData, uaCancelNonceCalldata,
} = OP_BUILDERS;

// The generic path stays (owner 2026-10-31, TS-D14): a mixed batch, an op with no named entry.
const MTX_TYPES = { EIP712Domain: SALTED_DOMAIN_TYPE, MetaTransaction: fields(`address from,bytes data,${E}`) };
const TRANSFER_TYPES = { EIP712Domain: SALTED_DOMAIN_TYPE, MetaTransfer: STRUCTS.MetaTransfer };
const TRADE_ORDER = STRUCTS.TradeOrder;
const ORDER_TYPES = { EIP712Domain: SALTED_DOMAIN_TYPE, TradeOrder: TRADE_ORDER };
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

/** The payee's side of receiver-pays (CTR-MTX-05/06), both paths: `td` is the `ReceiverFee` (`mtxPayReceiverFee`) or
 *  `UAReceiverFee` (`uaPayReceiverFee`; `payee` then a 32-byte id, `padId` for a native one) to co-sign, nesting the payer's
 *  payment (TS-D19). The payment must be the one the payee expects, as `checkPayment` checks it for the payer: to `payee`,
 *  `amount` (× 10^`decimals`) with the request's `entryRef` on lane `payLane(entryRef)` nonce 0, the contract's shape (fee
 *  NONE, relayer bound: mode 1), in `expectedToken`'s domain salted with `chainUid`. The fee is the payee's own: non-zero, at
 *  most the amount and `maxFee` (default 0), to the `feeRecipient` it named, with a near deadline. The server supplies only
 *  the payment's `from` / `validUntil` / `relayer` and the fee's `validUntil`. Returns {digest, paymentDigest (what the
 *  payer signs), payer, fee, feeRecipient}. */
export function checkReceiverFee(td, { payee, chainId, chainUid, amount, decimals, entryRef, expectedToken, maxFee = 0, feeRecipient,
  now = Math.floor(Date.now() / 1000), maxWindow = 86400 }) {
  const ua = td && td.primaryType === 'UAReceiverFee';
  if (!td || !(ua || td.primaryType === 'ReceiverFee')) refuse('this is not a receiver fee');
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
  const paymentDigest = digestOf((ua ? uaMetaTransferTypedData : metaTransferTypedData)({ name: d.name, contract: expectedToken,
    chainId, chainUid, message: payment }));
  const digest = digestOf((ua ? uaReceiverFeeTypedData : receiverFeeTypedData)({ name: d.name, contract: expectedToken, chainId,
    chainUid, message: { payment, fee, feeRecipient, validUntil } }));
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

/** A relay-fee job (CTR-MTX-27, TS-D19) on `router` (`MtxRelayFee`, executor `executor`): `inner` (optional) is the call's
 *  own typed data on `target`, a named entry's or a `MetaTransaction`; a relayer it binds (`MODE_RESTRICT_RELAYER`) is set
 *  to the executor (left open otherwise; bound to anything else: refused). Open mode by default (`payee` unset: the payment
 *  goes to the router, which pays whoever submits); `payee` binds it (never the executor). `ua`: the payer `from` and
 *  `payee` are 32-byte ids. Returns {call (the inner typed data to sign first, or null), prompt {call, payment}: both intents
 *  for one review, payment(callData) → {ref, lane, typedData, digest, calldata(sig)}}: `callData` is the call with its own
 *  signature (`<op>Calldata`, `mtxExecuteCalldata`); the payment is `RelayFee{from, target, callDataHash, payee, value:
 *  amount, validUntil, relayer: router}` (`UARelayFee` on ids), on lane `payLane(ref)` with nonce 0 implicit; `calldata` is
 *  the router's `relay(target, callData, token, from, payee, value, validUntil, sig)` / `uaRelay(…, UASig)`. */
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
    const lane = payLane(ref);
    const typedData = (ua ? uaRelayFeeTypedData : relayFeeTypedData)({ name, contract: token, chainId, chainUid,
      message: { from, target, callDataHash: hex(keccak_256(asBytes(callData))), payee: to, value: amount, validUntil, relayer: router } });
    const t = typedData.message;
    const id = ua ? 'bytes32' : 'address';
    const sigType = ua ? abiType('UASig') : 'bytes';
    const calldata = (sig) => abiCall(`${ua ? 'uaRelay' : 'relay'}(address,bytes,address,${id},${id},uint256,uint256,${sigType})`,
      ['address', 'bytes', 'address', id, id, 'uint256', 'uint256', sigType],
      [target, asBytes(callData), token, t.from, t.payee, t.value, t.validUntil, ua ? abiValue('UASig', uaSigOf(sig)) : asBytes(sig)]);
    return { ref, lane, typedData, digest: digestOf(typedData), calldata };
  };
  return { call, prompt, payment };
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
  if (op === 'WrapOrder' || op === 'UAWrapOrder') refuse('a wrap order is checked by checkWrapOrder (CLI-SGN-36)');
  const o = TYPED_OPS[op];
  if (!o || !td || td.primaryType !== op) refuse('this is not the operation you asked for');
  const m = td.message || {};
  const d = td.domain || {};
  if (!same(d.verifyingContract, contract)) refuse('the operation is not on the contract you chose');
  requireWhole(op, message, o.types, o.envelope, m.mode);
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

/** `InvalidateNonces(from, batch, minNonce)` in the domain that holds the orders (the sell token, or the DEX for an outside
 *  token). */
export function invalidateNoncesTypedData({ name = 'SCaaS MetaToken', contract, chainId, chainUid, from, batch, minNonce }) {
  return { types: INVALIDATE_TYPES, primaryType: 'InvalidateNonces', domain: salted({ name, contract, chainId, chainUid }),
    message: { from, batch: String(batch), minNonce: String(minNonce) } };
}

const CANCELS = ['CancelOrder', 'CancelUAOrder', 'CancelWrapOrder', 'CancelUAWrapOrder', 'CancelDexOrder'];

/** A cancel the user chose: the nested cancel of the client's own stored `order` (TS-D19: `td.primaryType` names the struct
 *  the order was signed in, `cancelOrderTypedData` … `cancelDexOrderTypedData`), or `InvalidateNonces(account, batch,
 *  minNonce)`, in the domain that holds the order (`contract`: the sell token, or the DEX). `ua`: the account is a 32-byte
 *  id and the invalidation is `UAInvalidateNonces` (CTR-DEX-25). Returns the digest. */
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
 *  selling `sellToken` (`outside`: an outside token, signed as `DexOrder` in the DEX's domain, CTR-DEX-18). The order
 *  itself must name a DEX on the signer's pinned list (or, for a wrap by signature as the chain takes it until C6, then
 *  `checkWrapOrder`, CLI-SGN-36: `dex` = `receiveToken` = a pinned wrapper and `minFill = amount`), fee at most 1 %, known flags (no ESCROW on an outside token), non-zero
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
  orderTerms(o, outside);
  if (wrappers.some((w) => same(w, o.dex))) {
    if (outside || !same(o.receiveToken, o.dex) || uint(o.minFill, 'minFill') !== uint(o.amount, 'the amount')) {
      refuse('a wrap by signature mints from this wrapper, all or nothing');
    }
  } else if (!dexes.some((x) => same(x, o.dex))) {
    refuse('the order names a DEX that is not on your chain profile');
  }
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
  return { digest, minFill, warnings: orderWarnings(o, account, none, ua) };
}

/** A wrap by signature that is exactly the one the client built (CLI-SGN-35, CLI-SGN-36, TS-D19): the `WrapOrder` (`ua`:
 *  `UAWrapOrder`) `order` (wrappedToken, amount, minMinted, minFill, fee, relayer, destination, flags, batch, optional
 *  validUntil) from `account`, in the domain of the underlying `sellToken`. A wrapper can pull `amount`, so it must be on the
 *  signer's pinned `wrappers`; all or nothing (`minFill = amount`), fee at most 1 %, known flags, non-zero amounts. The server
 *  supplies only the nonce and, when `order` has none, `validUntil` within the window. Returns {digest, minFill, warnings}. */
export function checkWrapOrder(td, { account, chainId, chainUid, order, sellToken, wrappers = [], ua = false,
  now = Math.floor(Date.now() / 1000), maxWindow = 30 * 86400 }) {
  const type = ua ? 'UAWrapOrder' : 'WrapOrder';
  if (!td || td.primaryType !== type) refuse('this is not the wrap order you asked for');
  const got = td.message || {};
  const none = ua ? ZERO_ID : ZERO_ADDRESS;
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
  return { digest, minFill, warnings: orderWarnings(o, account, none, ua) };
}

/** `checkWrapOrder` on the UA path: `UAWrapOrder`, `account` and `destination` 32-byte ids. */
export const checkUAWrapOrder = (td, opts) => checkWrapOrder(td, { ...opts, ua: true });

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
