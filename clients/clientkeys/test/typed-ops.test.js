// typed-signing C1: the named typed entries against smartcontracts/vectors/typed/typed_ops.json. The plan's truncated
// typehashes and Appendix X.4's type strings are written out here on purpose, apart from the table in src/evm.js: a
// mismatch is a stop-and-report, never a silent correction of either side. Forge pins the C0 entries against the same
// rows (test/metatx/NamedEntry.t.sol); C2-C6 are written to the rest.
// ua-mtx-merge T11 (CTR-MTX-30, plan MD-7): one signed entry per operation. A merged op has one row, `UA<Op>`, whose entry
// is `mtx<Op>(UAEnvelope, …, UASig)`; the address rows of merged ops are in vectors/typed/legacy/ua-mtx-merge/.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import * as evm from '../src/evm.js';
import * as zether from '../src/zether.js';
import { hex, fromHex, keccak_256, utf8ToBytes, concatBytes, abiEncode, word } from '../src/bytes.js';
import { expectedCall, norm } from '../scripts/typed-ops-expected.mjs';
import * as reg from '../src/regulated.js';
import { creationInitArgs } from '../src/factory.js';

const { TYPED_OPS, hashTypedData, hashStruct, checkOp, checkWrapOrder, checkUAWrapOrder, checkTradeOrder, checkCancel, encodeType } = evm;
const V = JSON.parse(readFileSync(new URL('../../../smartcontracts/vectors/typed/typed_ops.json', import.meta.url)));
const builders = { ...evm.OP_BUILDERS, ...evm, ...zether };
const sel = (sig) => hex(keccak_256(utf8ToBytes(sig)).subarray(0, 4));
const ZERO = '0x' + '00'.repeat(20);
const lower = (s) => s.replace(/^UA/, 'ua').replace(/^[A-Z]/, (c) => c.toLowerCase());
const domainOf = (r, d) => ({ name: d.domain.name, contract: d.domain.verifyingContract, chainId: d.domain.chainId,
  chainUid: d.domain.salt });
const rows = () => Object.entries(V.ops);
// group 3g: a per-kind row (`UAPqzRollOver`) names its primary type and its builders
const prim = (name) => TYPED_OPS[name].primary;
const bld = (name) => TYPED_OPS[name].builder;
const domains = (r) => Object.entries(r.domains);

// The plan's Part C tables, truncated as they are printed there (`Execute`: `cast keccak` of its type string).
// ua-mtx-merge T11: the address rows of merged ops left (MD-7); `UACancelNonce` is the ordered cancel (Q2) and the mandate
// wallets' `UA<Op>` rows are new (Q6): their full typehashes from `cast keccak` of the contract's type strings.
const PLAN = {
  CancelNonce: '0x77d6b4d4…f857dbf4bc', UABurn: '0xeed13c9a…fe9238f540',
  Wrap: '0xd2fe0a6e…b2adac31', WrapLeg: '0x5846a8b8…46912147', UAUnwrap: '0x914311a4…84d3aa93',
  UAUnwrapLeg: '0xdbbb5d3f…f7cc1a48', AddReserve: '0x189280a9…a2162dfe',
  WrapToUA: '0x3a2ec74d…25895dcde', UAUnwrapToUA: '0x8bb1bc05…af2d9a04',
  UAShield: '0xf86740a1…efb08337', WrapShield: '0x9188b9d0…b011ef',
  UARollOver: '0xd5ad0bcf…0465fd', UAPqzRollOver: '0x900621af…44e200a9bb75', UAPrepareAcc: '0xe173bbc7…ef43cc',
  AddKey: '0x9d156f1f…7244a6bb', RemoveKey: '0xcef46d27…618280b3', RotateKey: '0x5b8f8761…64fb0777',
  SetGuardian: '0xd2603850…6b967689f6', CancelRecovery: '0x3df995dd…1213adda', Execute: '0xe0b649e9…c6053f1df7',
  UAReceiverFee: '0xb12d2a08…7c75021a', UARelayFee: '0x220269b9…e493e43ea5', UAWrapOrder: '0x2a01cb57…fc04533c',
  CancelUAOrder: '0x47eb46c7…a1eaeba', CancelUAWrapOrder: '0x7679e176…2326d9d', CancelDexOrder: '0xcc35e105…f433c6',
  ZetherRollOver: '0x52e2c8f8…71768b1e', ZetherSetRollOverMode: '0x5f5a4ffa…4d55e09d', PqzAuth: '0x380b0de6…42644e6f',
  UACancelNonce: '0xcd17c2129240241748e841a7f0572558b9c5a900a47bc540170a8c258d291c54',
  UASetMandate: '0x77cac4912d9b5ea899e4894cd527290f239809543c0a3604b89ef74796d88492',
  UASetPayee: '0xf0fb362dece88eadf659a55ed5c2606877293dbd69f9bb7eba806da921a77dc4',
  UARevokeMandate: '0x8ec86d41c994f21c46c1517876704534ac3d564d82e844ec73b07d6f4b07b8bc',
  UAPayUnderMandate: '0xadbc54026c0db2f3af4387e08d6db8d717cb74af436468a089f09d377d6f0119',
  UADelegateRevoke: '0x774892773810b24a4c22164980cf38c17d181e11c99acc17c7229238a11035e0',
  UAExecute: '0x0d4d513cf9b5169c6422cb757a9af6c10be34ccd883caa3a1d18d165cf9ea413',
  // pay-meta-tax T41: `UARelayFee` with batch, nonce (T38, RelayFeeRouter.t.sol's pin); `UAPayWithTax` (paytax.json, forge-written)
  UAPayWithTax: '0x4a5f25751af8f3abdc633328e8e9871ea0ebeb4084608bb83ae8140803a21857',
};

// Appendix X.4, the nested strings verbatim.
const E = 'uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient';
const TA = 'PqzTransferArgs(uint64 p,uint256 validUntilBlock,uint256 shieldIn,bytes32 fromUA,uint64 keyVersion,bytes32 toUA,bytes32 beneficiaryUA,bytes16 salt,bytes32 ownTag,bytes u,bytes vTo,bytes vFrom,bytes vAuditor,bytes sealedMemo)';
const LEG = 'PqzLeg(bytes32 ua,bytes v,bytes vAuditor)';
const MA = 'PqzMultiArgs(uint64 p,uint256 validUntilBlock,uint256 shieldIn,bytes32 fromUA,uint64 keyVersion,bytes32 beneficiaryUA,uint256 decoyFee,bytes16 salt,bytes32 ownTag,bytes[] u,PqzLeg[] legs,bytes vFrom,bytes sealedMemo)';
const BA = 'PqzBurnArgs(uint64 p,uint256 validUntilBlock,uint256 shieldIn,bytes32 fromUA,uint64 keyVersion,bytes32 beneficiaryUA,bytes32 ownTag,bytes u,bytes vFrom)';
const UW = 'Unwrap(address underlying,bytes32 recipient,uint256 amount,uint256 minOut)';
const G1 = 'G1(bytes32 x0,bytes32 x1,bytes32 y0,bytes32 y1)';
const ZS = 'ZetherSingle(uint64 accSeq,uint64 sendCounter,uint256 validUntilBlock,bytes16 salt,bytes32 beneficiaryUA,G1 yFrom,G1 yTo,G1 cOut,G1 dOut,G1 cDeb,G1 cAud)';
const ZL = 'ZetherLeg(G1 yTo,G1 cOut,G1 cAud,G1 dAud)';
const ZM = 'ZetherMulti(uint64 accSeq,uint64 sendCounter,uint256 validUntilBlock,bytes16 salt,bytes32 beneficiaryUA,uint256 decoyFee,G1 yFrom,G1 dOut,G1 cDeb,ZetherLeg[] legs,bytes sealedMemo)';
const ZB = 'ZetherBurn(uint64 accSeq,uint64 sendCounter,uint256 validUntilBlock,bytes32 beneficiaryUA,G1 yFrom)';
const X4 = {
  PqzTransferSingle: ['PqzTransferArgs args,bytes proof,bytes accHint', TA],
  PqzTransferSingleCompact: ['PqzTransferArgs args,bytes proof,bytes accHint', TA],
  PqzTransfer: ['PqzMultiArgs args,bytes proof,bytes accHint', LEG + MA],
  PqzTransferCompact: ['PqzMultiArgs args,bytes proof,bytes accHint', LEG + MA],
  PqzUnshield: ['PqzBurnArgs args,uint256 amount,bytes32 recipient,bytes proof,bytes accHint', BA],
  PqzUnshieldUnwrap: ['PqzBurnArgs args,Unwrap unwrap,bytes proof,bytes accHint', BA + UW],
  ZetherTransferSingle: ['ZetherSingle args,bytes proof', G1 + ZS],
  ZetherTransfer: ['ZetherMulti args,bytes proof', G1 + ZL + ZM],
  ZetherTransferCompact: ['ZetherMulti args,bytes proof', G1 + ZL + ZM],
  ZetherUnshield: ['ZetherBurn args,uint256 amount,bytes32 recipient,bytes proof', G1 + ZB],
  ZetherUnshieldUnwrap: ['ZetherBurn args,Unwrap unwrap,bytes proof', G1 + UW + ZB],
  RollOverSigned: ['bytes32 ua,uint64 expectedPendingSeq,uint64 validUntilBlock', ''],
  SetRollOverMode: ['bytes32 ua,uint8 rollOverMode,uint64 validUntilBlock', ''],
  RollOverBatch: ['bytes32[] uas', ''],
};

// The named entries: one per op on `mtxSelectors()`, whose length is read from the Solidity (the Zether and wrapped PQZ kinds:
// the table is in the library, `ZetherLib.normalSelectors` since CTR-ZTH-94, size lever 1). ua-mtx-merge T11: an address
// row only where the op has no merged entry (the five wraps on tokens, CTR-MTX-30 §2.1; every op of `SmartKeyAccount`).
// ua-mtx-merge T66b: the normal, wrapped and normal PQZ kinds' tables moved to their `<X>Core` (`_mtxSelectorsBody`).
const SOURCES = { NormalToken: 'metatx/NormalTokenCore', WrappedToken: 'metatx/WrappedTokenCore', NormalZetherToken: 'zether/ZetherLib',
  WrappedZetherToken: 'zether/ZetherWrappedLib', NormalPqzToken: 'pqz/NormalPqzTokenCore', WrappedPqzToken: 'pqz/PqzWrappedLib',
  MandateWallet: 'wallet/MandateWallet', SmartKeyAccount: 'account/SmartKeyAccount' };
const mtxSelectorCount = (contract) => Number(/new bytes4\[\]\((\d+)\)/.exec(
  readFileSync(new URL(`../../../smartcontracts/evm/src/${SOURCES[contract]}.sol`, import.meta.url), 'utf8'))[1]);
const ADDRESS_ENTRIES = { NormalToken: 0, WrappedToken: 4, NormalZetherToken: 0, WrappedZetherToken: 5, NormalPqzToken: 0,
  WrappedPqzToken: 5, MandateWallet: 0, SmartKeyAccount: 7 };

// A minimal strict ABI decoder, apart from the encoder in src/bytes.js.
function tupleMembers(t) {
  const out = [];
  let depth = 0;
  let start = 1;
  for (let i = 1; i < t.length - 1; i++) {
    if (t[i] === '(') depth++;
    else if (t[i] === ')') depth--;
    else if (t[i] === ',' && depth === 0) { out.push(t.slice(start, i)); start = i + 1; }
  }
  out.push(t.slice(start, -1));
  return out;
}
const dyn = (t) => t === 'bytes' || t === 'string' || t.endsWith('[]') || (t[0] === '(' && tupleMembers(t).some(dyn));
const size = (t) => (t[0] === '(' && !dyn(t) ? tupleMembers(t).reduce((n, m) => n + size(m), 0) : 32);
function decodeList(types, b) {
  let at = 0;
  return types.map((t) => {
    const v = dyn(t) ? decodeOne(t, b.subarray(Number(BigInt(hex(b.subarray(at, at + 32)))))) : decodeOne(t, b.subarray(at));
    at += dyn(t) ? 32 : size(t);
    return v;
  });
}
function decodeOne(t, b) {
  if (t.endsWith('[]')) {
    const n = Number(BigInt(hex(b.subarray(0, 32))));
    return decodeList(Array(n).fill(t.slice(0, -2)), b.subarray(32));
  }
  if (t[0] === '(') return decodeList(tupleMembers(t), b);
  if (t === 'bytes') return hex(b.subarray(32, 32 + Number(BigInt(hex(b.subarray(0, 32))))));
  if (t === 'string') return new TextDecoder('utf-8', { fatal: true }).decode(b.subarray(32, 32 + Number(BigInt(hex(b.subarray(0, 32))))));
  if (t === 'address') return hex(b.subarray(12, 32));
  if (t === 'bytes32') return hex(b.subarray(0, 32));
  if (/^bytes\d+$/.test(t)) return hex(b.subarray(0, Number(t.slice(5))));
  if (t === 'bool') return BigInt(hex(b.subarray(0, 32))) === 1n;
  return BigInt(hex(b.subarray(0, 32))).toString();
}
const paramTypes = (abi) => tupleMembers(abi.slice(abi.indexOf('(')));
test('every typehash pinned: the plan\'s truncated value, keccak256(typeString), table = vector', () => {
  const mismatch = [];
  for (const [name, want] of Object.entries(PLAN)) {
    const [a, b = ''] = want.split('…');
    const got = TYPED_OPS[name]?.typehash ?? 'no row';
    if (!(got.startsWith(a) && got.endsWith(b))) mismatch.push(`${name}: plan ${want}, table ${got}`);
  }
  assert.deepEqual(mismatch, []);
  assert.deepEqual(Object.keys(V.ops).sort(), Object.keys(TYPED_OPS).sort());
  assert.deepEqual(Object.keys(TYPED_OPS).filter((n) => !PLAN[n] && !/^UA/.test(n)), [], 'a row with no pin');
  for (const [name, r] of rows()) {
    assert.equal(r.typeString, TYPED_OPS[name].typeString, name);
    assert.equal(r.typehash, TYPED_OPS[name].typehash, name);
    assert.equal(hex(keccak_256(utf8ToBytes(r.typeString))), r.typehash, name);
    assert.equal(encodeType(r.types, prim(name)), r.typeString, name);
  }
});

test('Appendix X.4: every confidential type string, its UA form only (the address twin retired); referenced types sorted', () => {
  assert.equal(Object.keys(X4).length, 14);
  for (const [name, [own, nested]] of Object.entries(X4)) {
    assert.equal(TYPED_OPS[name], undefined, `${name}: the address row retired (MD-7)`);
    assert.equal(TYPED_OPS[`UA${name}`].typeString, `UA${name}(bytes32 from,${own},${E})${nested}`, name);
  }
});

test('kept unchanged: the type strings the plan freezes', () => {
  const order = (id) => `(${id} from,address receiveToken,uint256 amount,uint256 receiveAmount,uint256 minFill,uint256 fee,`
    + `address relayer,address dex,${id} destination,uint8 flags,uint256 batch,uint256 nonce,uint256 validUntil)`;
  const transfer = (id) => `(${id} from,${id} to,uint256 value,bytes32 entryRef,${E})`;
  const nested = (name) => TYPED_OPS[name].typeString.slice(name.length);
  assert.ok(nested('CancelUAOrder').endsWith(`UATradeOrder${order('bytes32')}`));
  assert.ok(nested('CancelDexOrder').endsWith(`DexOrder(address sellToken,TradeOrder order)TradeOrder${order('address')}`));
  assert.ok(nested('UAReceiverFee').endsWith(`UAMetaTransfer${transfer('bytes32')}`));
});

test('the table covers every allowlisted entry of every contract, one row per op, and only them', () => {
  const count = (contract, ua) => Object.values(TYPED_OPS).filter((o) => o.envelope && o.ua === ua && o.on.includes(contract)).length;
  for (const [contract, addressN] of Object.entries(ADDRESS_ENTRIES)) {
    assert.equal(count(contract, false) + count(contract, true), mtxSelectorCount(contract), contract);
    assert.equal(count(contract, false), addressN, contract);
  }
  // ua-mtx-merge T11 (MD-7): 112 − 45 retired − the wallet's five address ops (Q6) + its six `UA<Op>` = 68; `UACancelNonce` an
  // envelope op now (Q2)
  // T34: + the router's eight regulated controls (regulated-kinds spec §3.1): 76, 67 envelope ops
  // pay-meta-tax T41: + `UAPayWithTax` (a raw struct) and the router's `UASetTaxRate`, `UASetTaxRecipient`: 79, 69
  // group 3g T54: the rollover one row per kind (`UARollOver` Zether, `UAPqzRollOver` PQZ with `keyVersion`): 80, 70
  // ua-mtx-merge T76: + the router's three creations (`UACreateToken`, `UACreateDex`, `UACreateInstance`): 83, 73
  // T46 (group 3f): + the router's three PQZ verifier ops (`UAPqzSetVerifier`, `UAPqzCancelVerifier`, `UAPqzRevokeVerifier`): 86, 76
  // group 3h T61: + the router's `UASetProofStore` (bit 24): 87, 77
  // group 3l: + the router's `UASetWrapLimits`, `UASetWrapMember`: 89, 79
  // round 3r: + the router's fifteen admin ops of the factory and a compliance registry: 104, 94
  // round 3s: + the router's `UASetAllowed`, `UASetDenied`, `UAEnableFeature`: 107, 97; round 3t: + `UASetVerifierFee`: 108, 98
  assert.equal(Object.keys(TYPED_OPS).length, 108);
  assert.equal(Object.values(TYPED_OPS).filter((o) => o.envelope).length, 98);
  for (const o of Object.values(TYPED_OPS)) {
    if (o.envelope) assert.ok(o.entry.startsWith('mtx'), o.primary);
    if (o.ua) assert.equal(o.fields[0].type, 'bytes32', o.primary);
  }
});

test('hashTypedData(td) == row.digest; the builder rebuilds the wallet\'s JSON; the row signs natively', () => {
  const pub = secp256k1.getPublicKey(fromHex(V.key.private), false);
  assert.equal(hex(keccak_256(pub.subarray(1)).subarray(12)), V.key.address);
  for (const [name, r] of rows()) {
    assert.ok(domains(r).length > 0, name);
    for (const [kind, d] of domains(r)) {
      const td = builders[`${bld(name)}TypedData`]({ ...domainOf(r, d), message: r.message });
      assert.deepEqual(td.message, r.message, `${name} ${kind}`);
      assert.equal(hex(hashTypedData(td)), d.digest, `${name} ${kind}`);
      assert.equal(hex(hashStruct(td.types, prim(name), td.message)), r.structHash, `${name} ${kind}`);
      assert.equal(hex(hashStruct(td.types, 'EIP712Domain', td.domain)), d.domainSeparator, `${name} ${kind}`);
      const digest = hashTypedData(td);
      const sig = fromHex(d.signature);
      assert.equal(sig.length, 65);
      const rec = secp256k1.Signature.fromBytes(sig.subarray(0, 64), 'compact').addRecoveryBit(sig[64] - 27);
      assert.equal(hex(rec.recoverPublicKey(digest).toBytes(false)), hex(pub), `${name} ${kind}`);
    }
  }
});

test('calldata decodes to the message: selector of the full signature, every parameter in place', () => {
  for (const [name, r] of rows()) {
    for (const [kind, d] of domains(r)) {
      if (!d.abi) { assert.equal(name, 'PqzAuth'); assert.equal(d.calldata, undefined); continue; }
      const data = fromHex(d.calldata);
      assert.equal(hex(data.subarray(0, 4)), sel(d.abi), `${name} ${kind}`);
      assert.equal(d.selector, sel(d.abi));
      const td = builders[`${bld(name)}TypedData`]({ ...domainOf(r, d), message: r.message });
      const again = builders[`${bld(name)}Calldata`](td, d.signature, d.extra);
      assert.equal(hex(again), d.calldata, `${name} ${kind}`);
      const got = decodeList(paramTypes(d.abi), data.subarray(4));
      assert.deepEqual(norm(got), norm(expectedCall(name, r, d)), `${name} ${kind}`);
    }
  }
});

test('the overloads: selectors from the full signature; the merged entries take the mtx names, UAEnvelope and UASig', () => {
  const env = '(address,uint256,uint256,uint256,uint32,address,uint256,address)';
  const uaEnv = '(bytes32,uint256,uint256,uint256,uint32,address,uint256,address)';
  const uaSig = '(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[])';
  const one = (name) => Object.values(V.ops[name].domains)[0];
  assert.equal(one('UAUnwrap').abi, `mtxUnwrap(${uaEnv},uint256,address,uint256,${uaSig})`);
  // R47: `mtxShield` takes `UASig` (the C0 spike's `bytes auth` is legacy)
  assert.equal(one('UAShield').abi, `mtxShield(${uaEnv},bytes32,uint256,${uaSig})`);
  assert.equal(one('UASetMandate').abi, `mtxSetMandate(${uaEnv},address,bytes32,uint128,uint128,uint64,uint64,${uaSig})`);
  assert.equal(one('UACancelNonce').abi, `mtxCancelNonce(${uaEnv},uint256,${uaSig})`);
  assert.equal(one('CancelNonce').abi, `mtxCancelNonce(${env},uint256,bytes)`, 'SmartKeyAccount keeps the address cancel');
  assert.equal(one('Wrap').abi, `mtxWrap(${env},uint256,bytes)`, 'a no-twin entry keeps Envelope and bytes');
  assert.notEqual(sel(one('UAShield').abi), sel('mtxShield(bytes32,uint256)'));
  // Payout on PQZ only: Appendix X.3's flat form does not compile there (evm-size-levers.md §7), the signed struct keeps both fields
  assert.ok(one('UAPqzUnshield').abi.includes(',(uint256,bytes32),bytes,'));
  assert.ok(one('UAZetherUnshield').abi.includes(',uint256,bytes32,bytes,'));
  assert.deepEqual(TYPED_OPS.UAPqzUnshield.fields.map((f) => f.name).slice(1, 3), ['args', 'amount']);
  for (const [name, r] of rows()) {
    for (const d of Object.values(r.domains)) assert.ok(!d.abi?.startsWith('ua'), `${name}: ${d.abi}`);
  }
});

test('a merged entry\'s calldata carries UASig{signature} for an EOA: empty keyData and members (R17, R47)', () => {
  let n = 0;
  for (const [name, r] of rows()) {
    if (!TYPED_OPS[name].ua || !TYPED_OPS[name].envelope) continue;
    for (const [kind, d] of domains(r)) {
      const got = decodeList(paramTypes(d.abi), fromHex(d.calldata).subarray(4));
      // pay-meta-tax T41: the mandate pay takes its `PayMeta` after the signature; T46 (group 3f): the six PQZ entries their
      // `PqzSignedVerdict`
      const after = name === 'UAPayUnderMandate' || /^UAPqz(Transfer|Unshield)/.test(name);
      assert.deepEqual(norm(got.at(after ? -2 : -1)), norm(['0x', d.signature, []]), `${name} ${kind}`);
      assert.equal(got[0][0], V.key.ua, `${name} ${kind}: the EOA's id, its address zero-padded`);
      n++;
    }
  }
  assert.ok(n > 50, `${n} merged rows`);
});

test('the mandate wallet rows are UA structs with bytes32 from, delegate, payee (Q6, MD-11)', () => {
  const W = {
    UASetMandate: 'address token,bytes32 delegate,uint128 maxPerPayment,uint128 maxPerPeriod,uint64 periodSeconds,uint64 expiry',
    UASetPayee: 'address token,bytes32 payee,bool allowed',
    UARevokeMandate: 'address token',
    UAPayUnderMandate: 'address token,bytes32 payee,uint256 amount,bytes32 entryRef,uint64 epoch',
    UADelegateRevoke: 'address token,uint64 epoch',
    UAExecute: 'address target,uint256 value,bytes data',
  };
  for (const [name, own] of Object.entries(W)) {
    const op = TYPED_OPS[name];
    assert.equal(op.typeString, `${name}(bytes32 from,${own},${E})`, name);
    assert.deepEqual([op.on, op.domains, op.entry], [['MandateWallet'], ['SCaaS MandateWallet'], `mtx${name.slice(2)}`], name);
    assert.deepEqual(Object.keys(V.ops[name].domains), ['wallet'], name);
    assert.deepEqual([V.ops[name].message.mode, V.ops[name].message.fee], [1, '0'], `${name}: fee mode NONE`);
  }
  for (const name of ['SetMandate', 'SetPayee', 'RevokeMandate', 'PayUnderMandate', 'DelegateRevoke']) {
    assert.equal(TYPED_OPS[name], undefined, `${name}: the address row retired`);
  }
  // `Execute` stays for `SmartKeyAccount` only; the wallet's cancel is the ordered `UACancelNonce`
  assert.deepEqual(TYPED_OPS.Execute.on, ['SmartKeyAccount']);
  assert.deepEqual(TYPED_OPS.CancelNonce.on, ['SmartKeyAccount']);
  assert.ok(TYPED_OPS.UACancelNonce.on.includes('MandateWallet'));
  assert.deepEqual(Object.keys(V.ops.CancelNonce.domains), ['account']);
});

test('the cancel row is ordered and native-capable: UACancelNonce(bytes32 from,uint256 lane,E) on mtxCancelNonce (Q2)', () => {
  const op = TYPED_OPS.UACancelNonce;
  assert.equal(op.typeString, `UACancelNonce(bytes32 from,uint256 lane,${E})`);
  assert.deepEqual([op.envelope, op.ua, op.entry], [true, true, 'mtxCancelNonce']);
  assert.deepEqual(op.on, ['NormalToken', 'NormalZetherToken', 'NormalPqzToken', 'WrappedToken', 'WrappedZetherToken', 'WrappedPqzToken',
    'MandateWallet', 'GovernanceRouter']);
  const r = V.ops.UACancelNonce;
  assert.deepEqual(Object.keys(r.domains), ['token', 'zether', 'pqz', 'wallet', 'gov_router']);
  assert.equal(r.message.from, V.key.ua, 'a native id: the EOA signs its own cancel');
  assert.ok('nonce' in r.message && 'lane' in r.message, 'ordered: the envelope nonce, the lane it bumps');
});

// governance T12 (spec §3.2): the router's rows read from the contract's own pin, test/governance/GovRouterTypehash.t.sol
// (literal strings and `cast keccak` hashes), apart from the table in src/evm.js: a mismatch is a stop-and-report.
// ua-mtx-merge T7 / T11 (R14): 19 `UA<Op>` rows on the `mtx<Op>` entries; the 19 address rows retired.
test('GovernanceRouter: 53 rows equal GovRouterTypehash.t.sol, target the first op word, fee mode NONE, the router domain only', () => {
  const sol = readFileSync(new URL('../../../smartcontracts/evm/test/governance/GovRouterTypehash.t.sol', import.meta.url), 'utf8');
  const pins = [...sol.matchAll(/keccak256\(\s*((?:"[^"]*"\s*)+)\)\);\s*assertEq\(T\.\w+, (0x[0-9a-f]{64})\)/g)]
    .map(([, lits, hash]) => [[...lits.matchAll(/"([^"]*)"/g)].map((x) => x[1]).join(''), hash]);
  // T32: + the eight regulated controls (regulated-kinds spec §3.1, CTR-GOV-20); T34 writes their rows
  // pay-meta-tax T39 / T41: + `UASetTaxRate`, `UASetTaxRecipient`; ua-mtx-merge T76: + the three creations
  // T46 (group 3f): the three PQZ verifier ops are checked against GovernanceRouterBase.sol in pqz-verdict.test.js, and here
  // too once this pin file carries them
  // group 3l: the leg array's two struct types are pinned there too, not rows
  // round 3r: + the fifteen admin ops of the factory and a compliance registry, and the `Env` struct pin
  const rows = pins.filter(([s]) => !s.startsWith('GrantTerms(') && !s.startsWith('WrapLimit(') && !s.startsWith('WrapLegLimits(')
    && !s.startsWith('Env('));
  const pqzPinned = rows.filter(([s]) => s.startsWith('UAPqz')).length;
  assert.ok(pqzPinned === 0 || pqzPinned === 3, `${pqzPinned} PQZ verifier pins`);
  // group 3h T61: + `UASetProofStore` (bit 24); group 3l: + `UASetWrapLimits`, `UASetWrapMember` and the two struct pins;
  // round 3s: + `UASetAllowed`, `UASetDenied`, `UAEnableFeature`; round 3t: + `UASetVerifierFee`
  assert.equal(pins.length - pqzPinned, 58);
  assert.equal(rows.length - pqzPinned, 54);
  for (const [s, hash] of rows) {
    const name = s.slice(0, s.indexOf('('));
    const op = TYPED_OPS[name];
    assert.ok(op, `${name}: no row`);
    assert.equal(op.typeString, s, name);
    assert.equal(op.typehash, hash, name);
    assert.deepEqual([op.on, op.domains, op.envelope], [['GovernanceRouter'], ['SCaaS GovernanceRouter'], true], name);
    assert.equal(op.ua, true, name);
    assert.equal(op.entry, `mtx${name.replace(/^UA/, '')}`, name);
    assert.deepEqual(op.fields[1], { name: 'target', type: 'address' }, `${name}: target is the first op word`);
    const r = V.ops[name];
    assert.deepEqual(Object.keys(r.domains), ['gov_router'], name);
    assert.equal(r.domains.gov_router.domain.name, 'SCaaS GovernanceRouter', name);
    // fee mode NONE; round 3r's `UAApproveTokenRelease`, round 3s's `UASetDenied` and round 3t's `UASetVerifierFee` leave the
    // relayer unbound too (mode 0, the canonical-zero rows)
    const open = name === 'UAApproveTokenRelease' || name === 'UASetDenied' || name === 'UASetVerifierFee';
    assert.deepEqual([r.message.mode, r.message.fee], [open ? 0 : 1, '0'], `${name}: fee mode NONE`);
  }
  assert.equal(Object.values(TYPED_OPS).filter((o) => o.on.includes('GovernanceRouter')).length, 58); // 3h T61: + UASetProofStore; 3l: + 2; 3r: + 15; 3s: + 3; 3t: + 1
  assert.equal(V.ops.UACancelNonce.domains.gov_router.domain.name, 'SCaaS GovernanceRouter');
  assert.equal(V.ops.CancelNonce.domains.gov_router, undefined);
});

// Round 3s (CTR-GOV-24, spec 2026-11-10-token-lists.md §6.2): the lists and `enableFeature`: the struct words after `target`,
// `accounts` hashed as the keccak256 of its words (the order and the length signed); `UASetDenied` at mode 0 with a non-zero
// relayer and fee recipient signs both as 0.
test('round 3s: UASetAllowed, UASetDenied, UAEnableFeature', () => {
  const JUNK = '0x' + 'ba'.repeat(20);
  for (const [name, params] of [['UASetAllowed', 'accounts,on'], ['UASetDenied', 'accounts,on'], ['UAEnableFeature', 'bit']]) {
    assert.deepEqual(TYPED_OPS[name].fields.map((f) => f.name).slice(0, -7), ['from', 'target', ...params.split(',')], name);
  }
  const r = V.ops.UASetDenied;
  assert.equal(r.message.accounts.length, 2);
  const d = r.domains.gov_router;
  const build = (m) => builders[`${bld('UASetDenied')}TypedData`]({ ...domainOf(r, d), message: m });
  const open = build({ ...r.message, relayer: JUNK, feeRecipient: JUNK });
  assert.deepEqual([open.message.relayer, open.message.feeRecipient], [ZERO, ZERO]);
  assert.equal(hex(hashTypedData(open)), d.digest, 'an unbound relayer and fee recipient sign as 0');
  const swapped = build({ ...r.message, accounts: [...r.message.accounts].reverse() });
  assert.notEqual(hex(hashTypedData(swapped)), d.digest, 'the order of accounts is signed');
  assert.equal(V.ops.UAEnableFeature.message.bit, 9);
});

// ua-mtx-merge T34 (regulated-kinds spec §3.1, §7; CTR-GOV-20 Change, owner 2026-11-06): the router's eight regulated controls.
// Each digest with a non-zero relayer and fee recipient left unbound (mode 0, then the row's mode 1 with feeRecipient unbound)
// equals the digest over the canonical 0, as `MetaTxLib.canon` hashes it, and differs from a hash of the raw message.
const REGULATED = { UAFreeze: 'account,ref,recordId', UAUnfreeze: 'account,ref', UAForceTransfer: 'recordId,amount',
  UAPause: 'ref,until', UAUnpause: 'ref', UARecordOrder: 'orderId,documentHash,subject,beneficiary,maxAmount,freezeUntil',
  UARevokeOrder: 'recordId,reasonRef', UAOperatorTransfer: 'account,to,amount,ref' };
test('the eight regulated router ops: from the signer, target, the direct entry\'s params; a non-zero unbound relayer or ' +
  'feeRecipient signs as 0', () => {
  const JUNK = '0x' + 'ba'.repeat(20);
  for (const [name, params] of Object.entries(REGULATED)) {
    const op = TYPED_OPS[name];
    assert.deepEqual(op.fields.map((f) => f.name).slice(0, -7), ['from', 'target', ...params.split(',')], name);
    const r = V.ops[name];
    const d = r.domains.gov_router;
    assert.deepEqual(Object.keys(r.domains), ['gov_router'], name);
    const at = domainOf(r, d);
    const build = (m) => builders[`${bld(name)}TypedData`]({ ...at, message: m });
    // the row's own mode (1: relayer bound, fee recipient unbound) with a non-zero fee recipient
    assert.equal(r.message.mode, 1, name);
    const given = build({ ...r.message, feeRecipient: JUNK });
    assert.equal(given.message.feeRecipient, ZERO, name);
    assert.equal(hex(hashTypedData(given)), d.digest, name);
    assert.notEqual(hex(hashStruct(given.types, name, { ...r.message, feeRecipient: JUNK })), r.structHash, `${name}: canon matters`);
    // mode 0: both unbound, both non-zero, both signed as 0
    const open = build({ ...r.message, mode: 0, relayer: JUNK, feeRecipient: JUNK });
    assert.deepEqual([open.message.relayer, open.message.feeRecipient], [ZERO, ZERO], name);
    assert.equal(hex(hashTypedData(open)), hex(hashTypedData(build({ ...r.message, mode: 0, relayer: ZERO, feeRecipient: ZERO }))), name);
    assert.notEqual(hex(hashTypedData(open)), d.digest, `${name}: the mode is signed`);
  }
  // the owner's ruling: the moved account is `account`, the signer `from`
  assert.ok(TYPED_OPS.UAOperatorTransfer.typeString.startsWith('UAOperatorTransfer(bytes32 from,address target,bytes32 account,bytes32 to,'));
  assert.equal(V.ops.UAFreeze.message.recordId, reg.recordId(V.ops.UARecordOrder.message.orderId, V.ops.UARecordOrder.message.subject,
    V.ops.UARecordOrder.message.beneficiary), 'one record across the rows');
});

test('a router row refuses a field off GrantTerms, a value out of range, a string bool, another domain; target is signed', () => {
  const B = evm.OP_BUILDERS;
  const at = { contract: '0x' + '7a'.repeat(20), chainId: 7622, chainUid: '0x' + 'c1'.repeat(32) };
  assert.throws(() => B.uaSetGrantTypedData({ ...at, message: { terms: { floor: 1 } } }), /floor is not a field of GrantTerms/);
  assert.throws(() => B.uaSetGrantTypedData({ ...at, message: { terms: { delegable: 'true' } } }), /Refusing to sign: .*bool/);
  assert.throws(() => B.uaSetGrantTypedData({ ...at, message: { terms: { window: 2 ** 32 } } }), /uint32/);
  assert.throws(() => B.uaGrantRoleTypedData({ ...at, message: { bit: 256 } }), /uint8/);
  assert.throws(() => B.uaGrantRoleTypedData({ ...at, message: { generation: 1 } }), /generation is not a field/);
  assert.throws(() => B.uaGrantRoleTypedData({ ...at, name: 'SCaaS MetaToken', message: {} }), /domain/);
  assert.throws(() => evm.uaBurnTypedData({ ...at, name: 'SCaaS GovernanceRouter', message: {} }), /domain/);
  assert.equal(B.uaMintToUATypedData({ ...at, message: {} }).domain.name, 'SCaaS GovernanceRouter');
  assert.equal(evm.uaCancelNonceTypedData({ ...at, name: 'SCaaS GovernanceRouter', message: {} }).domain.name, 'SCaaS GovernanceRouter');
  assert.equal(B.grantRoleTypedData, undefined, 'the address router ops retired (R14)');
  const m = { target: '0x' + '11'.repeat(20), bit: 1, account: '0x' + '22'.repeat(32) };
  const digest = (x) => hex(hashTypedData(B.uaGrantRoleTypedData({ ...at, message: x })));
  assert.notEqual(digest(m), digest({ ...m, target: '0x' + '12'.repeat(20) }));
});

test('checkOp refuses every changed field; the server supplies only the envelope', () => {
  const NOW = 1_800_000_000;
  for (const [name, r] of rows()) {
    if (name.endsWith('WrapOrder') && !name.startsWith('Cancel')) continue; // checkWrapOrder, below
    for (const [kind, d] of domains(r)) {
      const at = { contract: d.domain.verifyingContract, chainId: d.domain.chainId, chainUid: d.domain.salt };
      const td = builders[`${bld(name)}TypedData`]({ ...domainOf(r, d), message: r.message });
      const want = { op: name, ...at, message: r.message, maxFee: 2n ** 255n, now: NOW, maxWindow: 86400 * 365,
        feeRecipient: r.message.feeRecipient, relayer: r.message.relayer };
      const ok = checkOp(td, want);
      assert.equal(hex(ok.digest), d.digest, `${name} ${kind}`);
      assert.equal(ok.op, name);
      // every leaf of the message, one at a time
      const leaves = [];
      const walk = (v, path) => {
        if (v && typeof v === 'object') for (const k of Object.keys(v)) walk(v[k], [...path, k]);
        else leaves.push(path);
      };
      walk(r.message, []);
      for (const path of leaves) {
        const bad = structuredClone(td);
        let o = bad.message;
        for (const k of path.slice(0, -1)) o = o[k];
        const k = path.at(-1);
        const v = o[k];
        o[k] = typeof v === 'boolean' ? !v : typeof v === 'number' ? v + 1
          : /^0x/.test(v) ? (v.length === 2 ? '0x00' : v.slice(0, -2) + (v.endsWith('00') ? '01' : '00'))
            : /^[0-9]+$/.test(v) ? String(BigInt(v) + 1n) : `${v}!`; // round 3r: a `string` (a deprecation's reason)
        assert.throws(() => checkOp(bad, want), /Refusing to sign/, `${name} ${kind} ${path.join('.')}`);
      }
    }
  }
});

// ua-mtx-merge fix (the ua-rs-sign sync's finding): the whole-message check runs over the row's STRUCT (`UARollOver` for the
// PQZ row `UAPqzRollOver`), as ua-rs checks it; by the row name it found no type, so an omitted field read as zero.
test('checkOp: a row whose struct name is not its row name still refuses an omitted field', () => {
  const NOW = 1_800_000_000;
  const named = rows().filter(([name]) => prim(name) !== name);
  assert.ok(named.some(([name]) => name === 'UAPqzRollOver'), 'the PQZ rollover row is one');
  for (const [name, r] of named) {
    for (const [kind, d] of domains(r)) {
      const at = { contract: d.domain.verifyingContract, chainId: d.domain.chainId, chainUid: d.domain.salt };
      const td = builders[`${bld(name)}TypedData`]({ ...domainOf(r, d), message: r.message });
      const want = { op: name, ...at, message: r.message, maxFee: 2n ** 255n, now: NOW, maxWindow: 86400 * 365,
        feeRecipient: r.message.feeRecipient, relayer: r.message.relayer };
      assert.equal(hex(checkOp(td, want).digest), d.digest, `${name} ${kind}: the whole message passes`);
      for (const k of Object.keys(r.message).filter((f) => !['batch', 'nonce', 'validUntil', 'mode', 'relayer', 'fee',
        'feeRecipient'].includes(f))) {
        const { [k]: _omitted, ...partial } = r.message;
        assert.throws(() => checkOp(td, { ...want, message: partial }), /missing/, `${name} ${kind} without ${k}`);
      }
      // the hazard itself: a field whose value is 0, omitted by the client, must not read as that 0
      const zero = { ...r.message, keyVersion: 0 };
      const tz = builders[`${bld(name)}TypedData`]({ ...domainOf(r, d), message: zero });
      checkOp(tz, { ...want, message: zero });
      const { keyVersion: _kv, ...noVersion } = zero;
      assert.throws(() => checkOp(tz, { ...want, message: noVersion }), /the expected keyVersion is missing/, `${name} ${kind}`);
    }
  }
});

test('checkOp: the deadline, the fee policy, the contract, the chain, the operation', () => {
  const NOW = 1_800_000_000;
  const TOKEN = '0x' + '7a'.repeat(20);
  const UID = '0x' + 'c1'.repeat(32);
  const ME = '0x' + '00'.repeat(12) + '11'.repeat(20);
  const RELAYER = '0x' + '22'.repeat(20);
  const FEE_TO = '0x' + '33'.repeat(20);
  const op = { wrapped: 1000000, recipient: '0x' + '44'.repeat(20), minOut: 990000, from: ME };
  const at = { name: 'SCaaS MetaToken', contract: TOKEN, chainId: 7622, chainUid: UID };
  const server = (over = {}, a = at) => evm.uaUnwrapTypedData({ ...a, message: { ...op, batch: 7, nonce: 3, validUntil: NOW + 600,
    mode: 0x13, relayer: RELAYER, fee: 10000, feeRecipient: FEE_TO, ...over } });
  const { name: _n, ...where } = at;
  const want = { op: 'UAUnwrap', ...where, message: op, maxFee: 10000, feeRecipient: FEE_TO, relayer: RELAYER, now: NOW };
  const ok = checkOp(server(), want);
  assert.deepEqual([ok.feeMode, ok.fee, ok.feeRecipient, ok.relayer, ok.entry], [1, 10000n, FEE_TO, RELAYER, 'mtxUnwrap']);
  checkOp(server({ nonce: 9, batch: 8 }), want); // lane, nonce and deadline are the server's unless the client pins them
  assert.throws(() => checkOp(server({ nonce: 9 }), { ...want, message: { ...op, nonce: 3 } }), /not the operation/);
  assert.throws(() => checkOp(server(), { ...want, maxFee: 9999 }), /above your limit/);
  assert.throws(() => checkOp(server({ feeRecipient: RELAYER }), want), /did not name/);
  assert.throws(() => checkOp(server({ relayer: FEE_TO }), want), /another relayer/);
  assert.throws(() => checkOp(server({ validUntil: NOW }), want), /deadline/);
  assert.throws(() => checkOp(server({ validUntil: NOW + 3601 }), want), /deadline/);
  assert.throws(() => checkOp(server({ fee: 10001 }), { ...want, maxFee: 10 ** 9 }), /above 1 %/);
  assert.throws(() => checkOp(server(), { ...want, op: 'UAUnwrapLeg' }), /not the operation/);
  assert.throws(() => checkOp(server(), { ...want, op: 'Unwrap' }), /not the operation/);
  assert.throws(() => checkOp(server(), { ...want, contract: '0x' + '7b'.repeat(20) }), /contract you chose/);
  assert.throws(() => checkOp(server(), { ...want, chainId: 1 }), /not the operation/);
  assert.throws(() => checkOp(server(), { ...want, chainUid: '0x' + '11'.repeat(32) }), /not the operation/);
  assert.throws(() => checkOp(undefined, want), /not the operation/);
  // PERCENT only on an AMOUNT op (CTR-MTX-20): `wrap` is ABSOLUTE
  const addr = '0x' + '11'.repeat(20);
  const wrap = evm.wrapTypedData({ ...at, message: { from: addr, amount: 5, validUntil: NOW + 60, mode: 0x10, fee: 1 } });
  assert.throws(() => checkOp(wrap, { op: 'Wrap', ...where, message: { from: addr, amount: 5 }, maxFee: 10, now: NOW }), /percentage fee/);
  // a signed field the server fills in is not the client's: a non-envelope op takes nothing from the server
  const nope = { ...server(), message: { ...server().message, batch: '-1' } };
  assert.throws(() => checkOp(nope, want), /Refusing to sign/);
});

test('canonical zero for an unbound relayer / fee recipient: envelope and nested UAMetaTransfer', () => {
  const A = '0x' + '0a'.repeat(20);
  const B = '0x' + '0b'.repeat(20);
  const at = { name: 'SCaaS MetaToken', contract: '0x' + '7a'.repeat(20), chainId: 7622, chainUid: '0x' + 'c1'.repeat(32) };
  const m = (mode) => evm.uaBurnTypedData({ ...at, message: { from: '0x' + '0a'.repeat(32), amount: 1, mode, relayer: A, feeRecipient: B } }).message;
  assert.deepEqual([m(0).relayer, m(0).feeRecipient], [ZERO, ZERO]);
  assert.deepEqual([m(1).relayer, m(1).feeRecipient], [A, ZERO]);
  assert.deepEqual([m(2).relayer, m(2).feeRecipient], [ZERO, B]);
  assert.deepEqual([m(3).relayer, m(3).feeRecipient], [A, B]);
  const open = evm.uaReceiverFeeTypedData({ ...at, message: { payment: { from: '0x' + '0a'.repeat(32), to: '0x' + '0b'.repeat(32), value: 1,
    mode: 0, relayer: A, feeRecipient: B }, fee: 1, feeRecipient: B, validUntil: 9 } }).message.payment;
  assert.deepEqual([open.relayer, open.feeRecipient], [ZERO, ZERO]);
  const ua = evm.uaReceiverFeeTypedData({ ...at, message: { payment: { from: '0x' + '0a'.repeat(32), to: '0x' + '0b'.repeat(32), value: 1,
    mode: 1, relayer: A, feeRecipient: B }, fee: 1, feeRecipient: B, validUntil: 9 } }).message.payment;
  assert.deepEqual([ua.relayer, ua.feeRecipient], [A, ZERO]);
  // the order's `relayer` is no envelope field: it stays
  assert.equal(evm.cancelUAOrderTypedData({ ...at, message: { order: { relayer: A } } }).message.order.relayer, A);
});

// spec §6 (Codex medium 3): a wallet hashes what it is shown, so the message handed to it carries the canonical 0 in an unbound
// field; the review shows the field as unbound. Every row, against its own digest, with a non-zero value in each unbound field.
test('an unbound relayer or feeRecipient is signed as 0 and shown as unbound: every envelope row, a non-zero value given', () => {
  const NOW = 1_800_000_000;
  const JUNK = '0x' + 'ba'.repeat(20);
  let relayerOpen = 0;
  let feeToOpen = 0;
  for (const [name, r] of rows()) {
    if (!TYPED_OPS[name].envelope) continue;
    for (const [kind, d] of domains(r)) {
      const mode = BigInt(r.message.mode);
      const given = { ...r.message, relayer: mode & 1n ? r.message.relayer : JUNK, feeRecipient: mode & 2n ? r.message.feeRecipient : JUNK };
      const td = builders[`${bld(name)}TypedData`]({ ...domainOf(r, d), message: given });
      assert.equal(hex(hashTypedData(td)), d.digest, `${name} ${kind}`);
      if (!(mode & 1n)) { assert.equal(td.message.relayer, ZERO, `${name} ${kind}`); relayerOpen++; }
      if (!(mode & 2n)) { assert.equal(td.message.feeRecipient, ZERO, `${name} ${kind}`); feeToOpen++; }
      const { batch, nonce, validUntil, mode: _m, relayer, fee, feeRecipient, ...own } = r.message;
      const ok = checkOp(td, { op: name, contract: d.domain.verifyingContract, chainId: d.domain.chainId, chainUid: d.domain.salt, message: own,
        maxFee: 2n ** 255n, now: NOW, maxWindow: 86400 * 365, feeRecipient: r.message.feeRecipient, relayer: r.message.relayer });
      assert.equal(hex(ok.digest), d.digest, `${name} ${kind}`);
      assert.equal(ok.relayer, mode & 1n ? r.message.relayer : null, `${name} ${kind}: shown as any relayer`);
      assert.equal(ok.feeRecipient, mode & 2n ? r.message.feeRecipient : null, `${name} ${kind}: shown as the submitter's choice`);
    }
  }
  assert.ok(feeToOpen > 0, 'a row with an unbound fee recipient');
  // a token row binds both (mode 0x13 / 0x23); the same op with mode 0: both unbound, both 0
  const r = V.ops.UABurn;
  const d = r.domains.token;
  const open = evm.uaBurnTypedData({ ...domainOf(r, d), message: { ...r.message, mode: 0, fee: 0, relayer: JUNK, feeRecipient: JUNK } });
  assert.deepEqual([open.message.relayer, open.message.feeRecipient], [ZERO, ZERO]);
  assert.equal(hex(hashTypedData(open)), hex(hashTypedData(evm.uaBurnTypedData({ ...domainOf(r, d), message: { ...r.message, mode: 0, fee: 0,
    relayer: ZERO, feeRecipient: ZERO } }))));
  // group 3h (plan T59): the six PQZ debit rows of release 3h leave both open (mode 0x20), given a non-zero relayer above; every
  // other row binds its relayer (the open case of a token op is the mode-0 burn above)
  const open3h = rows().filter(([, x]) => x.release === '3h').length;
  assert.equal(open3h, 6, 'the six 3h rows');
  // round 3r: `UAApproveTokenRelease` leaves both open too (mode 0), given a non-zero relayer and fee recipient above
  assert.equal(TYPED_OPS.UAApproveTokenRelease && V.ops.UAApproveTokenRelease.message.mode, 0);
  // round 3t: `UASetVerifierFee` too (mode 0), the row with a non-zero unbound relayer and fee recipient given above
  assert.equal(V.ops.UASetVerifierFee.message.mode, 0);
  assert.equal(relayerOpen, open3h + 3, 'the 3h rows, UAApproveTokenRelease, UASetDenied (round 3s) and UASetVerifierFee leave the relayer open');
});

test('the builder refuses a field off the struct, a value out of range, a domain the op does not live in', () => {
  const at = { name: 'SCaaS MetaToken', contract: '0x' + '7a'.repeat(20), chainId: 7622, chainUid: '0x' + 'c1'.repeat(32) };
  assert.throws(() => evm.uaBurnTypedData({ ...at, message: { amountt: 1 } }), /amountt/);
  assert.throws(() => evm.uaSetMandateTypedData({ ...at, name: undefined, message: { periodSeconds: 2n ** 64n } }), /uint64/);
  assert.throws(() => evm.uaSetMandateTypedData({ ...at, name: undefined, message: { delegate: '0x' + 'd2'.repeat(20) } }), /32 bytes/);
  assert.throws(() => evm.uaBurnTypedData({ ...at, name: 'SCaaS MandateWallet', message: {} }), /domain/);
  assert.throws(() => evm.uaSetMandateTypedData({ ...at, name: 'SCaaS MetaToken', message: {} }), /domain/, 'a wallet row in the token domain');
  assert.equal(evm.uaSetMandateTypedData({ ...at, name: undefined, message: {} }).domain.name, 'SCaaS MandateWallet');
  assert.equal(evm.addKeyTypedData({ ...at, name: undefined, message: {} }).domain.name, 'SCaaS SmartKeyAccount');
  assert.equal(evm.uaBurnTypedData({ ...at, name: 'SCaaS PqzToken', message: {} }).domain.name, 'SCaaS PqzToken');
});

test('EIP-712 by the MetaMask v4 rules: bytes16 right-padded, arrays element by element, nested structs hashed', () => {
  const types = { Leg: [{ name: 'a', type: 'bytes' }], Top: [{ name: 's', type: 'bytes16' }, { name: 'xs', type: 'bytes[]' },
    { name: 'legs', type: 'Leg[]' }, { name: 'ids', type: 'bytes32[]' }, { name: 'ok', type: 'bool' }] };
  const s = '0x' + 'ab'.repeat(16);
  const id = '0x' + '11'.repeat(32);
  const k = keccak_256;
  const legH = k(concatBytes(k(utf8ToBytes('Leg(bytes a)')), k(fromHex('0x01'))));
  const th = k(utf8ToBytes('Top(bytes16 s,bytes[] xs,Leg[] legs,bytes32[] ids,bool ok)Leg(bytes a)'));
  const want = k(concatBytes(th, fromHex(s), new Uint8Array(16), k(concatBytes(k(fromHex('0x01')), k(fromHex('0x0203')))),
    k(legH), k(fromHex(id)), abiEncode(['bool'], [true])));
  assert.equal(hex(hashStruct(types, 'Top', { s, xs: ['0x01', '0x0203'], legs: [{ a: '0x01' }], ids: [id], ok: true })), hex(want));
  assert.equal(hex(hashStruct({ T: [{ name: 'xs', type: 'bytes[]' }] }, 'T', { xs: [] })),
    hex(k(concatBytes(k(utf8ToBytes('T(bytes[] xs)')), k(new Uint8Array(0))))));
});

test('abiEncode: nested dynamic tuples, arrays of tuples, bytes16, bool (abi.encode by hand)', () => {
  const W = (n) => n.toString(16).padStart(64, '0');
  const b = abiEncode(['(uint8,bytes)', '(bytes32,bytes)[]', 'bytes16', 'bool'],
    [[7, '0xaa'], [['0x' + '11'.repeat(32), '0xbbcc']], '0x' + 'dd'.repeat(16), true]);
  const want = W(0x80n) + W(0x100n) + 'dd'.repeat(16) + '00'.repeat(16) + W(1n)
    + W(7n) + W(0x40n) + W(1n) + 'aa' + '00'.repeat(31)                  // the first tuple
    + W(1n) + W(0x20n) + '11'.repeat(32) + W(0x40n) + W(2n) + 'bbcc' + '00'.repeat(30); // the array
  assert.equal(hex(b), '0x' + want);
});

// ---------------------------------------------------------------- independent review of C1

const R_NOW = 1_800_000_000;
const R_AT = { name: 'SCaaS MetaToken', contract: '0x' + '7a'.repeat(20), chainId: 7622, chainUid: '0x' + 'c1'.repeat(32) };
const R_ME = '0x' + '00'.repeat(12) + '11'.repeat(20);
const R_RELAYER = '0x' + '22'.repeat(20);
const R_FEE_TO = '0x' + '33'.repeat(20);
const R_WRAPPER = '0x' + '44'.repeat(20);
const R_OP = { from: R_ME, wrapped: 7, recipient: '0x' + '55'.repeat(20), minOut: 0 };
const rUnwrap = (over = {}) => evm.uaUnwrapTypedData({ ...R_AT, message: { ...R_OP, validUntil: R_NOW + 60, ...over } });
const rWant = (message, over = {}) => ({ op: 'UAUnwrap', contract: R_AT.contract, chainId: R_AT.chainId, chainUid: R_AT.chainUid, message,
  now: R_NOW, ...over });

test('checkWrapOrder: CLI-SGN-35 / -36 on the real UAWrapOrder; the server supplies only the nonce and an in-window deadline', () => {
  const order = { wrappedToken: R_WRAPPER, amount: 1000, minMinted: 990, minFill: 1000, fee: 3000, relayer: R_RELAYER, flags: 1, batch: 1,
    validUntil: R_NOW + 600 };
  const server = (o = {}, nonce = 5) => evm.uaWrapOrderTypedData({ ...R_AT, message: { ...order, from: R_ME, nonce, ...o } });
  const want = { account: R_ME, chainId: R_AT.chainId, chainUid: R_AT.chainUid, order, sellToken: R_AT.contract, wrappers: [R_WRAPPER], now: R_NOW };
  const ok = checkWrapOrder(server(), want);
  assert.equal(hex(ok.digest), hex(hashTypedData(server())));
  assert.deepEqual([ok.minFill, ok.warnings], [1000n, []]);
  checkWrapOrder(server({}, 9), want); // the nonce is the server's
  const late = { ...order };
  delete late.validUntil;
  checkWrapOrder(server({ validUntil: R_NOW + 86400 }), { ...want, order: late }); // and so is a deadline the order leaves open
  const no = (td, w, why) => assert.throws(() => checkWrapOrder(td, { ...want, ...w }), why);
  no(server(), { wrappers: [] }, /wrapper is not on your chain profile/);
  no(server(), { wrappers: ['0x' + '45'.repeat(20)] }, /wrapper is not on your chain profile/);
  no(server({ minFill: 1 }), { order: { ...order, minFill: 1 } }, /all or nothing/);
  no(server({ fee: 500000 }), { order: { ...order, fee: 500000 } }, /above 1 %/);
  no(server({ flags: 7 + 8 }), { order: { ...order, flags: 15 } }, /unknown order flags/);
  no(server({ flags: 2 }), { order: { ...order, flags: 2 } }, /unknown order flags/);
  no(server({}, 2n ** 128n), {}, /2\^128/);
  no(server({ minMinted: 0 }), { order: { ...order, minMinted: 0 } }, /amounts are malformed/);
  no(server({ amount: 0, minFill: 0 }), { order: { ...order, amount: 0, minFill: 0 } }, /amounts are malformed/);
  no(server({ validUntil: R_NOW }), { order: { ...order, validUntil: R_NOW } }, /deadline/);
  // the wrapper can pull `amount`: the server may not name another, nor change a term
  no(server({ wrappedToken: '0x' + '45'.repeat(20) }), {}, /not the wrap order/);
  no(server({ minMinted: 1 }), {}, /not the wrap order/);
  no(server({ destination: '0x' + '66'.repeat(32) }), {}, /not the wrap order/);
  no(server(), { sellToken: '0x' + '7b'.repeat(20) }, /not the wrap order/);
  no(server(), { account: '0x' + '00'.repeat(12) + '22'.repeat(20) }, /not the wrap order/);
  no(undefined, {}, /not the wrap order/);
  no(evm.uaTradeOrderTypedData({ token: R_AT.contract, chainId: R_AT.chainId, chainUid: R_AT.chainUid, order: { from: R_ME, nonce: 5 } }), {},
    /not the wrap order/);
  const away = { ...order, destination: '0x' + '66'.repeat(32), relayer: ZERO };
  assert.deepEqual(checkWrapOrder(server({ destination: away.destination, relayer: ZERO }), { ...want, order: away }).warnings,
    ['someone else receives the proceeds', 'any submitter may settle this order and earn the relayer share']);
  // ua-mtx-merge T11 (R39): the address `WrapOrder` left the token; `checkUAWrapOrder` is the same check
  assert.deepEqual(checkUAWrapOrder(server(), want).warnings, []);
  assert.equal(evm.wrapOrderTypedData, undefined);
  const legacyForm = { ...server(), primaryType: 'WrapOrder' };
  assert.throws(() => checkWrapOrder(legacyForm, want), /not the wrap order/);
});

test('checkOp refuses a wrap order: its rules cannot be bypassed; the cancel of one still goes through checkCancel', () => {
  for (const [op, build] of [['UAWrapOrder', evm.uaWrapOrderTypedData]]) {
    const td = build({ ...R_AT, message: {} });
    assert.throws(() => checkOp(td, { op, contract: R_AT.contract, chainId: R_AT.chainId, chainUid: R_AT.chainUid, message: td.message }),
      /Refusing to sign: .*checkWrapOrder/);
  }
});

test('after C6 a wrap is only a UAWrapOrder: checkTradeOrder and checkCancel refuse the UATradeOrder form', () => {
  const order = { receiveToken: R_WRAPPER, amount: 1000, receiveAmount: 990, minFill: 1000, fee: 3000, relayer: R_RELAYER, dex: R_WRAPPER,
    flags: 1, batch: 1, validUntil: R_NOW + 600 };
  const where = { account: R_ME, chainId: R_AT.chainId, chainUid: R_AT.chainUid };
  const td = evm.uaTradeOrderTypedData({ token: R_AT.contract, ...where, order: { ...order, from: R_ME, nonce: 5 } });
  // the wrapper on the DEX list changes nothing: the chain hashes `dex == receiveToken` as a wrap order
  assert.throws(() => checkTradeOrder(td, { ...where, ua: true, order, sellToken: R_AT.contract, dexes: [R_WRAPPER], now: R_NOW }),
    /a wrap by signature is a WrapOrder/);
  // the positive control: one field differs, `receiveToken`
  const buys = '0x' + '77'.repeat(20);
  const held = { ...order, receiveToken: buys };
  checkTradeOrder(evm.uaTradeOrderTypedData({ token: R_AT.contract, ...where, order: { ...held, from: R_ME, nonce: 5 } }),
    { ...where, ua: true, order: held, sellToken: R_AT.contract, dexes: [R_WRAPPER], now: R_NOW });
  const bare = { ...where, contract: R_AT.contract };
  const cancel = evm.cancelUAOrderTypedData({ ...R_AT, message: { order: td.message } });
  assert.throws(() => checkCancel(cancel, { ...bare, order: td.message }), /cancelled as a CancelUAWrapOrder/);
  const plain = evm.cancelUAOrderTypedData({ ...R_AT, message: { order: { ...td.message, receiveToken: buys } } });
  assert.equal(hex(checkCancel(plain, { ...bare, order: plain.message.order })), hex(hashTypedData(plain)));
  // the wrap order's own cancel is taken
  const { receiveToken, receiveAmount, dex, ...rest } = td.message;
  const w = { ...rest, wrappedToken: receiveToken, minMinted: receiveAmount };
  const wrapCancel = evm.cancelUAWrapOrderTypedData({ ...R_AT, message: { order: w } });
  assert.equal(hex(checkCancel(wrapCancel, { ...bare, order: wrapCancel.message.order })), hex(hashTypedData(wrapCancel)));
  // ua-mtx-merge T11 (R12): the token's address `TradeOrder` and its cancels left; the DEX's `DexOrder` stays (outside tokens)
  assert.equal(evm.cancelOrderTypedData, undefined);
  assert.throws(() => evm.tradeOrderTypedData({ token: R_AT.contract, chainId: R_AT.chainId, chainUid: R_AT.chainUid, order: held }),
    /a SCaaS sell token takes a UATradeOrder/);
  const held5 = evm.uaTradeOrderTypedData({ token: R_AT.contract, ...where, order: { ...held, from: R_ME, nonce: 5 } });
  assert.throws(() => checkTradeOrder({ ...held5, primaryType: 'TradeOrder' }, { ...where, order: held, sellToken: R_AT.contract,
    dexes: [R_WRAPPER], now: R_NOW }), /not the trade order/);
  assert.throws(() => checkTradeOrder(held5, { ...where, ua: false, order: held, sellToken: R_AT.contract, dexes: [R_WRAPPER], now: R_NOW }),
    /a SCaaS sell token takes a UATradeOrder/);
  assert.throws(() => checkCancel({ ...plain, primaryType: 'CancelOrder' }, { ...bare, order: plain.message.order }), /not the cancel/);
});

test('checkOp keeps a relayer or fee recipient the client named: refused when the mode bit would drop it', () => {
  const msg = { ...R_OP };
  assert.throws(() => checkOp(rUnwrap(), rWant({ ...msg, relayer: R_RELAYER })), /relayer you named is not bound/);
  assert.throws(() => checkOp(rUnwrap({ mode: 2, feeRecipient: R_FEE_TO }), rWant({ ...msg, relayer: R_RELAYER })), /relayer you named is not bound/);
  assert.throws(() => checkOp(rUnwrap(), rWant({ ...msg, feeRecipient: R_FEE_TO })), /fee recipient you named is not bound/);
  assert.throws(() => checkOp(rUnwrap({ mode: 1, relayer: R_RELAYER }), rWant({ ...msg, feeRecipient: R_FEE_TO }, { relayer: R_RELAYER })),
    /fee recipient you named is not bound/);
  // bound, or left open, or the zero address: fine
  checkOp(rUnwrap({ mode: 1, relayer: R_RELAYER }), rWant({ ...msg, relayer: R_RELAYER }));
  checkOp(rUnwrap({ mode: 2, feeRecipient: R_FEE_TO }), rWant({ ...msg, feeRecipient: R_FEE_TO }, { feeRecipient: R_FEE_TO }));
  checkOp(rUnwrap(), rWant({ ...msg, relayer: ZERO, feeRecipient: ZERO }));
  checkOp(rUnwrap(), rWant(msg));
  // nested too: a payment whose own mode would drop the relayer it names
  const payment = { from: R_ME, to: '0x' + '22'.repeat(32), value: 5, entryRef: '0x' + '09'.repeat(32), batch: 1, nonce: 0, validUntil: 9, mode: 0,
    relayer: R_RELAYER, fee: 0, feeRecipient: ZERO };
  const rf = { payment, fee: 1, feeRecipient: R_FEE_TO, validUntil: 9 };
  assert.throws(() => checkOp(evm.uaReceiverFeeTypedData({ ...R_AT, message: rf }), rWant(rf, { op: 'UAReceiverFee' })),
    /relayer you named is not bound/);
});

test('an omitted expectation is no "expect zero": every own field is the client\'s, in full', () => {
  const miss = /Refusing to sign: the expected .* is missing/;
  const { minOut, ...noMinOut } = R_OP;
  assert.equal(minOut, 0);
  assert.throws(() => checkOp(rUnwrap(), rWant(noMinOut)), miss);
  assert.throws(() => checkOp(rUnwrap({ recipient: ZERO }), rWant({ ...R_OP, recipient: undefined })), miss);
  const { from, ...noFrom } = R_OP;
  assert.equal(from, R_ME);
  assert.throws(() => checkOp(rUnwrap(), rWant(noFrom)), miss);
  const addr = '0x' + '11'.repeat(20);
  const toUA = evm.wrapToUATypedData({ ...R_AT, message: { from: addr, amount: 1, underlying: R_WRAPPER, validUntil: R_NOW + 60 } });
  assert.throws(() => checkOp(toUA, rWant({ from: addr, amount: 1, underlying: R_WRAPPER }, { op: 'WrapToUA' })), miss);
  const zero = evm.cancelUAOrderTypedData({ ...R_AT, message: {} });
  assert.throws(() => checkOp(zero, rWant(undefined, { op: 'CancelUAOrder' })), /Refusing to sign/);
  assert.throws(() => checkOp(zero, rWant({}, { op: 'CancelUAOrder' })), miss);
  assert.throws(() => checkOp(zero, rWant({ order: {} }, { op: 'CancelUAOrder' })), miss);
  assert.throws(() => checkOp(zero, rWant({ order: { ...zero.message.order, flags: undefined } }, { op: 'CancelUAOrder' })), miss);
  // arrays and nested structs too; the whole struct passes; `{op}` alone says Refusing, not a TypeError
  const batch = evm.OP_BUILDERS.uaRollOverBatchTypedData({ ...R_AT, name: 'SCaaS ZetherToken', message: { from: R_ME, uas: [], validUntil: R_NOW + 60 } });
  assert.throws(() => checkOp(batch, rWant({ from: R_ME }, { op: 'UARollOverBatch' })), miss);
  checkOp(zero, rWant(zero.message, { op: 'CancelUAOrder' }));
  assert.throws(() => checkOp(rUnwrap(), { op: 'UAUnwrap', contract: R_AT.contract }), /Refusing to sign/);
  assert.throws(() => checkOp(rUnwrap(), { op: 'UAUnwrap', contract: R_AT.contract, message: null }), /Refusing to sign/);
  // the empty string is no number
  assert.throws(() => evm.uaBurnTypedData({ ...R_AT, message: { amount: '' } }), /Refusing to sign/);
  assert.throws(() => evm.uaBurnTypedData({ ...R_AT, message: { amount: '   ' } }), /Refusing to sign/);
  assert.throws(() => checkOp(rUnwrap(), rWant({ ...R_OP, minOut: '' })), /Refusing to sign/);
  assert.throws(() => word(''), /not a number/);
  assert.throws(() => abiEncode(['uint256'], ['']), /not a number/);
  assert.equal(evm.uaBurnTypedData({ ...R_AT, message: { amount: '0x10' } }).message.amount, '16');
  assert.equal(evm.uaBurnTypedData({ ...R_AT, message: { amount: 16n } }).message.amount, '16');
});

test('a bool is true or false: \'false\' is no truth, in the builder, the hash or the calldata', () => {
  assert.throws(() => evm.uaSetPayeeTypedData({ ...R_AT, name: 'SCaaS MandateWallet', message: { allowed: 'false' } }), /Refusing to sign: .*bool/);
  assert.throws(() => evm.uaSetPayeeTypedData({ ...R_AT, name: 'SCaaS MandateWallet', message: { allowed: 1 } }), /Refusing to sign: .*bool/);
  assert.throws(() => zether.pqzAuthTypedData({ ...R_AT, name: 'SCaaS PqzToken', message: { auditorOn: 'false' } }), /Refusing to sign: .*bool/);
  assert.equal(evm.uaSetPayeeTypedData({ ...R_AT, name: 'SCaaS MandateWallet', message: { allowed: false } }).message.allowed, false);
  assert.equal(evm.uaSetPayeeTypedData({ ...R_AT, name: 'SCaaS MandateWallet', message: {} }).message.allowed, false);
  const types = { T: [{ name: 'ok', type: 'bool' }] };
  assert.throws(() => hashStruct(types, 'T', { ok: 'false' }), /bool/);
  assert.throws(() => abiEncode(['bool'], ['false']), /bool/);
  const td = evm.uaSetPayeeTypedData({ ...R_AT, name: 'SCaaS MandateWallet', message: { allowed: true, validUntil: R_NOW + 60 } });
  td.message.allowed = 'false';
  const id0 = '0x' + '00'.repeat(32);
  assert.throws(() => checkOp(td, rWant({ from: id0, token: ZERO, payee: id0, allowed: true }, { op: 'UASetPayee' })), /Refusing to sign/);
});

test('calldata refuses what the entry cannot verify: the missing signature, an encoded account blob; a shared op names its domain', () => {
  const row = (name) => V.ops[name];
  const one = (name) => Object.values(row(name).domains)[0];
  const tdOf = (name) => {
    const d = one(name);
    return builders[`${bld(name)}TypedData`]({ ...domainOf(row(name), d), message: row(name).message });
  };
  for (const name of ['UAPqzTransferSingle', 'UAPqzTransfer', 'UAPqzUnshield', 'UAPqzUnshieldUnwrap']) {
    assert.throws(() => builders[`${bld(name)}Calldata`](tdOf(name), one(name).signature), /Refusing to sign: pqzAuth is required/, name);
    assert.throws(() => builders[`${bld(name)}Calldata`](tdOf(name), one(name).signature, { pqzAuth: {} }), /pqzAuth is required/, name);
  }
  for (const name of ['UARollOverSigned', 'UASetRollOverMode']) {
    assert.throws(() => builders[`${bld(name)}Calldata`](tdOf(name), one(name).signature), /Refusing to sign: ownerSig is required/, name);
  }
  assert.throws(() => evm.uaReceiverFeeCalldata(tdOf('UAReceiverFee'), one('UAReceiverFee').signature), /payerSig is required/);
  assert.throws(() => evm.uaUnwrapCalldata(tdOf('UAUnwrap')), /signature is required/);
  assert.throws(() => evm.uaUnwrapCalldata(tdOf('UAUnwrap'), '0x'), /signature is required/);
  // the account's own: a raw signature is 65 bytes, anything else names its key
  const add = tdOf('AddKey');
  const raw = one('AddKey').signature;
  const blob = evm.accountSignature(0, [], fromHex(raw));
  assert.throws(() => evm.addKeyCalldata(add, blob), /Refusing to sign: .*keyIndex/);
  assert.throws(() => evm.addKeyCalldata(add, hex(blob)), /Refusing to sign: .*keyIndex/);
  assert.equal(hex(evm.addKeyCalldata(add, raw)), one('AddKey').calldata);
  assert.equal(hex(evm.addKeyCalldata(add, { keyIndex: 0, proof: [], signature: raw })), one('AddKey').calldata);
  // a shared op names its domain, a single-domain one need not
  const { name, ...unnamed } = R_AT;
  assert.equal(name, 'SCaaS MetaToken');
  assert.throws(() => evm.uaUnwrapTypedData({ ...unnamed, message: {} }), /Refusing to sign: .*name/);
  assert.throws(() => evm.uaCancelNonceTypedData({ ...unnamed, message: {} }), /Refusing to sign: .*name/);
  assert.equal(evm.uaSetPayeeTypedData({ ...unnamed, message: {} }).domain.name, 'SCaaS MandateWallet');
  assert.equal(evm.executeTypedData({ ...unnamed, message: {} }).domain.name, 'SCaaS SmartKeyAccount');
});

const NO_CAST = spawnSync('cast', ['--version']).error ? 'no cast on PATH' : false;
test('typed-ops-cast-check: a swapped parameter is refused against the message, not passed as a round trip', { skip: NO_CAST }, () => {
  const script = new URL('../scripts/typed-ops-cast-check.mjs', import.meta.url).pathname;
  const dir = mkdtempSync(join(tmpdir(), 'typed-ops-swap-'));
  try {
    const run = (ops) => {
      const f = join(dir, 'row.json');
      writeFileSync(f, JSON.stringify({ key: V.key, ops }));
      return spawnSync(process.execPath, [script, f], { encoding: 'utf8' });
    };
    assert.equal(run({ UAUnwrap: V.ops.UAUnwrap }).status, 0);
    const swapped = structuredClone(V.ops.UAUnwrap);
    const d = Object.values(swapped.domains)[0];
    const words = d.calldata.slice(10).match(/.{64}/g);
    [words[8], words[10]] = [words[10], words[8]]; // `wrapped` and `minOut`, after the eight envelope words
    d.calldata = d.calldata.slice(0, 10) + words.join('');
    const r = run({ UAUnwrap: swapped });
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /UAUnwrap token: calldata/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ua-mtx-merge T76 (chain-neutral spec §4.4, S3): the router's creations sign `initHash = keccak256(initArgs)` (`initCall`
// for an instance); the entry takes the bytes from `extra`, and bytes that are not the signed hash are refused.
test('the router creations: initHash binds the extra bytes', () => {
  for (const [name, field] of [['UACreateToken', 'initArgs'], ['UACreateDex', 'initArgs'], ['UACreateInstance', 'initCall']]) {
    const op = TYPED_OPS[name];
    const r = V.ops[name];
    const d = r.domains.gov_router;
    const td = { types: op.types, primaryType: op.primary, domain: d.domain, message: r.message };
    assert.equal(hex(keccak_256(fromHex(d.extra[field]))), r.message.initHash, name);
    assert.equal(hex(op.call(td, d.signature, d.extra).data), d.calldata, name);
    assert.throws(() => op.call(td, d.signature, { [field]: '0x00' }), /not the signed initHash/, name);
    assert.throws(() => op.call(td, d.signature, {}), new RegExp(`needs extra.${field}`), name);
  }
});

// Fable recheck 2 P3-7 (NODE-JOB-26): a creation's named config and its `initArgs` (smartcontracts/vectors/factory/create_config.json,
// checked against the Solidity structs by forge `CreateConfigKat.t.sol`, read by the node too): the bytes a client sends in
// `extra.initArgs` are the ones the node rebuilds from the named config, and they bind the signed `initHash`.
test('the router creations: the named config vector binds initHash', () => {
  const K = JSON.parse(readFileSync(new URL('../../../smartcontracts/vectors/factory/create_config.json', import.meta.url)));
  for (const [name, key] of [['UACreateToken', 'token'], ['UACreateDex', 'dex']]) {
    const op = TYPED_OPS[name];
    const d = V.ops[name].domains.gov_router;
    const { initArgs, initHash } = K[key];
    assert.equal(hex(keccak_256(fromHex(initArgs))), initHash, name);
    const td = { types: op.types, primaryType: op.primary, domain: d.domain, message: { ...V.ops[name].message, initHash } };
    const data = hex(op.call(td, d.signature, { initArgs }).data);
    assert.ok(data.includes(initArgs.slice(2)), `${name}: the calldata carries initArgs`);
    assert.throws(() => op.call(td, d.signature, { initArgs: d.extra.initArgs }), /not the signed initHash/, name);
    // Fable recheck 3 R3-7: the named config itself encodes to the row's initArgs (the same struct order forge checks)
    assert.equal(creationInitArgs(key, K[key].config), initArgs, `${name}: config -> initArgs`);
    assert.throws(() => creationInitArgs(key, { ...K[key].config, extra: 1 }), /no field extra/, name);
    const { grantDelay, ...missing } = K[key].config;
    assert.throws(() => creationInitArgs(key, missing), /config.grantDelay: missing/, name);
  }
  const swapped = { ...K.dex.config, grantDelay: K.dex.config.relayerSharePpm, relayerSharePpm: Number(K.dex.config.grantDelay) };
  assert.notEqual(creationInitArgs('dex', swapped), K.dex.initArgs, 'two fields swapped: other bytes');
  assert.throws(() => creationInitArgs('token', { ...K.token.config, decimals: 256 }), /out of uint8/);
});
