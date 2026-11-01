// typed-signing C1: the named typed entries against smartcontracts/vectors/typed/typed_ops.json. The plan's truncated
// typehashes and Appendix X.4's type strings are written out here on purpose, apart from the table in src/evm.js: a
// mismatch is a stop-and-report, never a silent correction of either side. Forge pins the C0 entries against the same
// rows (test/metatx/NamedEntry.t.sol); C2-C6 are written to the rest.
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

const { TYPED_OPS, hashTypedData, hashStruct, checkOp, checkWrapOrder, checkUAWrapOrder, checkTradeOrder, checkCancel, encodeType } = evm;
const V = JSON.parse(readFileSync(new URL('../../../smartcontracts/vectors/typed/typed_ops.json', import.meta.url)));
const builders = { ...evm, ...zether };
const sel = (sig) => hex(keccak_256(utf8ToBytes(sig)).subarray(0, 4));
const ZERO = '0x' + '00'.repeat(20);
const lower = (s) => s.replace(/^UA/, 'ua').replace(/^[A-Z]/, (c) => c.toLowerCase());
const domainOf = (r, d) => ({ name: d.domain.name, contract: d.domain.verifyingContract, chainId: d.domain.chainId,
  chainUid: d.domain.salt });
const rows = () => Object.entries(V.ops);
const domains = (r) => Object.entries(r.domains);

// The plan's Part C tables, truncated as they are printed there (`Execute`: `cast keccak` of its type string).
const PLAN = {
  CancelNonce: '0x77d6b4d4…f857dbf4bc', Burn: '0x89bf2320…a925bbf925', UABurn: '0xeed13c9a…fe9238f540',
  Wrap: '0xd2fe0a6e…b2adac31', WrapLeg: '0x5846a8b8…46912147', Unwrap: '0x7272e86d…4f4af742', UAUnwrap: '0x914311a4…84d3aa93',
  UnwrapLeg: '0xaccc7271…0c972a58e2', UAUnwrapLeg: '0xdbbb5d3f…f7cc1a48', AddReserve: '0x189280a9…a2162dfe',
  WrapToUA: '0x3a2ec74d…25895dcde', UnwrapToUA: '0x9df2319a…1cdb4732', UAUnwrapToUA: '0x8bb1bc05…af2d9a04',
  Shield: '0x60bd57f6…3d165ad', UAShield: '0xf86740a1…efb08337', WrapShield: '0x9188b9d0…b011ef',
  RollOver: '0xcd3e09a9…5e9df', UARollOver: '0xd5ad0bcf…0465fd', PrepareAcc: '0xf3726703…b16834',
  UAPrepareAcc: '0x33e99b3c…c460e5', SetMandate: '0x826b6b56…df746275', SetPayee: '0x0c9b1692…fa8a5985',
  RevokeMandate: '0x4e4e4b87…c4f9d14', PayUnderMandate: '0xe68ac74c…f2d82acf', DelegateRevoke: '0xd36a49f4…8d1983f9da',
  AddKey: '0x9d156f1f…7244a6bb', RemoveKey: '0xcef46d27…618280b3', RotateKey: '0x5b8f8761…64fb0777',
  SetGuardian: '0xd2603850…6b967689f6', CancelRecovery: '0x3df995dd…1213adda', Execute: '0xe0b649e9…c6053f1df7',
  ReceiverFee: '0x7c08a6ca…28232305', UAReceiverFee: '0xb12d2a08…7c75021a', RelayFee: '0x8018f06a…302b7909f',
  UARelayFee: '0x77fa32c7…cd3eb54d', WrapOrder: '0x07a267c8…29eb6555', UAWrapOrder: '0x2a01cb57…fc04533c',
  CancelOrder: '0x29879342…42e789a5', CancelUAOrder: '0x47eb46c7…a1eaeba', CancelWrapOrder: '0xf2691001…e9ae399',
  CancelUAWrapOrder: '0x7679e176…2326d9d', CancelDexOrder: '0xcc35e105…f433c6', UACancelNonce: '0xf5d81494…5ca227',
  ZetherRollOver: '0x52e2c8f8…71768b1e', ZetherSetRollOverMode: '0x5f5a4ffa…4d55e09d', PqzAuth: '0x380b0de6…42644e6f',
};

// Appendix X.4, the nested strings verbatim.
const E = 'uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient';
const TA = 'PqzTransferArgs(uint64 p,uint256 validUntilBlock,uint256 shieldIn,bytes32 fromUA,bytes32 toUA,bytes32 beneficiaryUA,bytes16 salt,bytes u,bytes vTo,bytes vFrom,bytes vAuditor,bytes sealedMemo)';
const LEG = 'PqzLeg(bytes32 ua,bytes v,bytes vAuditor)';
const MA = 'PqzMultiArgs(uint64 p,uint256 validUntilBlock,uint256 shieldIn,bytes32 fromUA,bytes32 beneficiaryUA,uint256 decoyFee,bytes16 salt,bytes[] u,PqzLeg[] legs,bytes vFrom,bytes sealedMemo)';
const BA = 'PqzBurnArgs(uint64 p,uint256 validUntilBlock,uint256 shieldIn,bytes32 fromUA,bytes32 beneficiaryUA,bytes u,bytes vFrom)';
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

// `mtx` entries: the length of `mtxSelectors()`, read from the Solidity (`WRAPPED_ZETHER`: its table is in the library, size lever 1). `ua` entries: an expected count, by hand, since
// `_uaAllowed` is an expression and states no count.
const SOURCES = { NormalToken: 'metatx/NormalToken', WrappedToken: 'metatx/WrappedToken', NormalZetherToken: 'zether/NormalZetherToken',
  WrappedZetherToken: 'zether/ZetherWrappedLib', NormalPqzToken: 'pqz/NormalPqzToken', WrappedPqzToken: 'pqz/WrappedPqzToken',
  MandateWallet: 'wallet/MandateWallet', SmartKeyAccount: 'account/SmartKeyAccount' };
const mtxSelectorCount = (contract) => Number(/new bytes4\[\]\((\d+)\)/.exec(
  readFileSync(new URL(`../../../smartcontracts/evm/src/${SOURCES[contract]}.sol`, import.meta.url), 'utf8'))[1]);
const EXPECTED_UA_ENTRIES = { NormalToken: 1, WrappedToken: 3, NormalZetherToken: 10, WrappedZetherToken: 13, NormalPqzToken: 9,
  WrappedPqzToken: 12, MandateWallet: 0, SmartKeyAccount: 0 };

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
const dyn = (t) => t === 'bytes' || t.endsWith('[]') || (t[0] === '(' && tupleMembers(t).some(dyn));
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
    const [a, b] = want.split('…');
    const got = TYPED_OPS[name].typehash;
    if (!(got.startsWith(a) && got.endsWith(b))) mismatch.push(`${name}: plan ${want}, table ${got}`);
  }
  assert.deepEqual(mismatch, []);
  assert.deepEqual(Object.keys(V.ops).sort(), Object.keys(TYPED_OPS).sort());
  for (const [name, r] of rows()) {
    assert.equal(r.typeString, TYPED_OPS[name].typeString, name);
    assert.equal(r.typehash, TYPED_OPS[name].typehash, name);
    assert.equal(hex(keccak_256(utf8ToBytes(r.typeString))), r.typehash, name);
    assert.equal(encodeType(r.types, name), r.typeString, name);
  }
});

test('Appendix X.4: every confidential type string and its UA twin, exactly; referenced types sorted', () => {
  assert.equal(Object.keys(X4).length, 14);
  for (const [name, [own, nested]] of Object.entries(X4)) {
    assert.equal(TYPED_OPS[name].typeString, `${name}(address from,${own},${E})${nested}`, name);
    assert.equal(TYPED_OPS[`UA${name}`].typeString, `UA${name}(bytes32 from,${own},${E})${nested}`, name);
  }
});

test('kept unchanged: the type strings the plan freezes', () => {
  const order = (id) => `(${id} from,address receiveToken,uint256 amount,uint256 receiveAmount,uint256 minFill,uint256 fee,`
    + `address relayer,address dex,${id} destination,uint8 flags,uint256 batch,uint256 nonce,uint256 validUntil)`;
  const transfer = (id) => `(${id} from,${id} to,uint256 value,bytes32 entryRef,${E})`;
  const nested = (name) => TYPED_OPS[name].typeString.slice(name.length);
  assert.ok(nested('CancelOrder').endsWith(`TradeOrder${order('address')}`));
  assert.ok(nested('CancelUAOrder').endsWith(`UATradeOrder${order('bytes32')}`));
  assert.ok(nested('CancelDexOrder').endsWith(`DexOrder(address sellToken,TradeOrder order)TradeOrder${order('address')}`));
  assert.ok(nested('ReceiverFee').endsWith(`MetaTransfer${transfer('address')}`));
  assert.ok(nested('UAReceiverFee').endsWith(`UAMetaTransfer${transfer('bytes32')}`));
});

test('the table covers every allowlisted entry of every contract, and only them', () => {
  const count = (contract, ua) => Object.values(TYPED_OPS).filter((o) => o.envelope && o.ua === ua && o.on.includes(contract)).length;
  for (const [contract, uaN] of Object.entries(EXPECTED_UA_ENTRIES)) {
    assert.deepEqual([count(contract, false), count(contract, true)], [mtxSelectorCount(contract), uaN], contract);
  }
  assert.equal(Object.keys(TYPED_OPS).length, 74);
  assert.equal(Object.values(TYPED_OPS).filter((o) => o.envelope).length, 59);
});

test('hashTypedData(td) == row.digest; the builder rebuilds the wallet\'s JSON; the row signs natively', () => {
  const pub = secp256k1.getPublicKey(fromHex(V.key.private), false);
  assert.equal(hex(keccak_256(pub.subarray(1)).subarray(12)), V.key.address);
  for (const [name, r] of rows()) {
    assert.ok(domains(r).length > 0, name);
    for (const [kind, d] of domains(r)) {
      const td = builders[`${lower(name)}TypedData`]({ ...domainOf(r, d), message: r.message });
      assert.deepEqual(td.message, r.message, `${name} ${kind}`);
      assert.equal(hex(hashTypedData(td)), d.digest, `${name} ${kind}`);
      assert.equal(hex(hashStruct(td.types, name, td.message)), r.structHash, `${name} ${kind}`);
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
      const td = builders[`${lower(name)}TypedData`]({ ...domainOf(r, d), message: r.message });
      const again = builders[`${lower(name)}Calldata`](td, d.signature, d.extra);
      assert.equal(hex(again), d.calldata, `${name} ${kind}`);
      const got = decodeList(paramTypes(d.abi), data.subarray(4));
      assert.deepEqual(norm(got), norm(expectedCall(name, r, d)), `${name} ${kind}`);
    }
  }
});

test('the overloads: selectors from the full signature, the C0 shapes', () => {
  const env = '(address,uint256,uint256,uint256,uint32,address,uint256,address)';
  const uaEnv = '(bytes32,uint256,uint256,uint256,uint32,address,uint256,address)';
  const uaSig = '(bytes,bytes,(uint16,bytes,bytes)[])';
  const one = (name) => Object.values(V.ops[name].domains)[0];
  assert.equal(one('Unwrap').abi, `mtxUnwrap(${env},uint256,address,uint256,bytes)`);
  assert.equal(one('Shield').abi, `mtxShield(${env},bytes32,uint256,bytes)`);
  assert.equal(one('UAShield').abi, `uaShield(${uaEnv},bytes32,uint256,bytes)`, 'C0 spike: `bytes auth` until C2 moves it to UASig');
  assert.equal(one('SetMandate').abi, `mtxSetMandate(${env},address,address,uint128,uint128,uint64,uint64,bytes)`);
  assert.equal(one('UAUnwrap').abi, `uaUnwrap(${uaEnv},uint256,address,uint256,${uaSig})`);
  assert.notEqual(sel(one('Shield').abi), sel('mtxShield(bytes32,uint256)'));
  // Payout on PQZ only: Appendix X.3's flat form does not compile there (evm-size-levers.md §7), the signed struct keeps both fields
  assert.ok(one('PqzUnshield').abi.includes(',(uint256,bytes32),bytes,'));
  assert.ok(one('ZetherUnshield').abi.includes(',uint256,bytes32,bytes,'));
  assert.deepEqual(TYPED_OPS.PqzUnshield.fields.map((f) => f.name).slice(1, 3), ['args', 'amount']);
});

test('checkOp refuses every changed field; the server supplies only the envelope', () => {
  const NOW = 1_800_000_000;
  for (const [name, r] of rows()) {
    if (name.endsWith('WrapOrder') && !name.startsWith('Cancel')) continue; // checkWrapOrder, below
    for (const [kind, d] of domains(r)) {
      const at = { contract: d.domain.verifyingContract, chainId: d.domain.chainId, chainUid: d.domain.salt };
      const td = builders[`${lower(name)}TypedData`]({ ...domainOf(r, d), message: r.message });
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
          : /^0x/.test(v) ? (v.length === 2 ? '0x00' : v.slice(0, -2) + (v.endsWith('00') ? '01' : '00')) : String(BigInt(v) + 1n);
        assert.throws(() => checkOp(bad, want), /Refusing to sign/, `${name} ${kind} ${path.join('.')}`);
      }
    }
  }
});

test('checkOp: the deadline, the fee policy, the contract, the chain, the operation', () => {
  const NOW = 1_800_000_000;
  const TOKEN = '0x' + '7a'.repeat(20);
  const UID = '0x' + 'c1'.repeat(32);
  const ME = '0x' + '11'.repeat(20);
  const RELAYER = '0x' + '22'.repeat(20);
  const FEE_TO = '0x' + '33'.repeat(20);
  const op = { wrapped: 1000000, recipient: '0x' + '44'.repeat(20), minOut: 990000, from: ME };
  const at = { name: 'SCaaS MetaToken', contract: TOKEN, chainId: 7622, chainUid: UID };
  const server = (over = {}, a = at) => evm.unwrapTypedData({ ...a, message: { ...op, batch: 7, nonce: 3, validUntil: NOW + 600,
    mode: 0x13, relayer: RELAYER, fee: 10000, feeRecipient: FEE_TO, ...over } });
  const { name: _n, ...where } = at;
  const want = { op: 'Unwrap', ...where, message: op, maxFee: 10000, feeRecipient: FEE_TO, relayer: RELAYER, now: NOW };
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
  assert.throws(() => checkOp(server(), { ...want, op: 'UnwrapLeg' }), /not the operation/);
  assert.throws(() => checkOp(server(), { ...want, contract: '0x' + '7b'.repeat(20) }), /contract you chose/);
  assert.throws(() => checkOp(server(), { ...want, chainId: 1 }), /not the operation/);
  assert.throws(() => checkOp(server(), { ...want, chainUid: '0x' + '11'.repeat(32) }), /not the operation/);
  assert.throws(() => checkOp(undefined, want), /not the operation/);
  // PERCENT only on an AMOUNT op (CTR-MTX-20): `wrap` is ABSOLUTE
  const wrap = evm.wrapTypedData({ ...at, message: { from: ME, amount: 5, validUntil: NOW + 60, mode: 0x10, fee: 1 } });
  assert.throws(() => checkOp(wrap, { op: 'Wrap', ...where, message: { from: ME, amount: 5 }, maxFee: 10, now: NOW }), /percentage fee/);
  // a signed field the server fills in is not the client's: a non-envelope op takes nothing from the server
  const nope = { ...server(), message: { ...server().message, batch: '-1' } };
  assert.throws(() => checkOp(nope, want), /Refusing to sign/);
});

test('canonical zero for an unbound relayer / fee recipient: envelope and nested MetaTransfer', () => {
  const A = '0x' + '0a'.repeat(20);
  const B = '0x' + '0b'.repeat(20);
  const at = { name: 'SCaaS MetaToken', contract: '0x' + '7a'.repeat(20), chainId: 7622, chainUid: '0x' + 'c1'.repeat(32) };
  const m = (mode) => evm.burnTypedData({ ...at, message: { from: A, amount: 1, mode, relayer: A, feeRecipient: B } }).message;
  assert.deepEqual([m(0).relayer, m(0).feeRecipient], [ZERO, ZERO]);
  assert.deepEqual([m(1).relayer, m(1).feeRecipient], [A, ZERO]);
  assert.deepEqual([m(2).relayer, m(2).feeRecipient], [ZERO, B]);
  assert.deepEqual([m(3).relayer, m(3).feeRecipient], [A, B]);
  const open = evm.receiverFeeTypedData({ ...at, message: { payment: { from: A, to: B, value: 1, mode: 0, relayer: A, feeRecipient: B },
    fee: 1, feeRecipient: B, validUntil: 9 } }).message.payment;
  assert.deepEqual([open.relayer, open.feeRecipient], [ZERO, ZERO]);
  const ua = evm.uaReceiverFeeTypedData({ ...at, message: { payment: { from: '0x' + '0a'.repeat(32), to: '0x' + '0b'.repeat(32), value: 1,
    mode: 1, relayer: A, feeRecipient: B }, fee: 1, feeRecipient: B, validUntil: 9 } }).message.payment;
  assert.deepEqual([ua.relayer, ua.feeRecipient], [A, ZERO]);
  // the order's `relayer` is no envelope field: it stays
  assert.equal(evm.cancelOrderTypedData({ ...at, message: { order: { relayer: A } } }).message.order.relayer, A);
});

test('the builder refuses a field off the struct, a value out of range, a domain the op does not live in', () => {
  const at = { name: 'SCaaS MetaToken', contract: '0x' + '7a'.repeat(20), chainId: 7622, chainUid: '0x' + 'c1'.repeat(32) };
  assert.throws(() => evm.burnTypedData({ ...at, message: { amountt: 1 } }), /amountt/);
  assert.throws(() => evm.setMandateTypedData({ ...at, name: undefined, message: { periodSeconds: 2n ** 64n } }), /uint64/);
  assert.throws(() => evm.burnTypedData({ ...at, name: 'SCaaS MandateWallet', message: {} }), /domain/);
  assert.equal(evm.setMandateTypedData({ ...at, name: undefined, message: {} }).domain.name, 'SCaaS MandateWallet');
  assert.equal(evm.addKeyTypedData({ ...at, name: undefined, message: {} }).domain.name, 'SCaaS SmartKeyAccount');
  assert.equal(evm.burnTypedData({ ...at, name: 'SCaaS PqzToken', message: {} }).domain.name, 'SCaaS PqzToken');
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
const R_ME = '0x' + '11'.repeat(20);
const R_RELAYER = '0x' + '22'.repeat(20);
const R_FEE_TO = '0x' + '33'.repeat(20);
const R_WRAPPER = '0x' + '44'.repeat(20);
const R_OP = { from: R_ME, wrapped: 7, recipient: '0x' + '55'.repeat(20), minOut: 0 };
const rUnwrap = (over = {}) => evm.unwrapTypedData({ ...R_AT, message: { ...R_OP, validUntil: R_NOW + 60, ...over } });
const rWant = (message, over = {}) => ({ op: 'Unwrap', contract: R_AT.contract, chainId: R_AT.chainId, chainUid: R_AT.chainUid, message,
  now: R_NOW, ...over });

test('checkWrapOrder: CLI-SGN-35 / -36 on the real WrapOrder; the server supplies only the nonce and an in-window deadline', () => {
  const order = { wrappedToken: R_WRAPPER, amount: 1000, minMinted: 990, minFill: 1000, fee: 3000, relayer: R_RELAYER, flags: 1, batch: 1,
    validUntil: R_NOW + 600 };
  const server = (o = {}, nonce = 5) => evm.wrapOrderTypedData({ ...R_AT, message: { ...order, from: R_ME, nonce, ...o } });
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
  no(server({ destination: '0x' + '66'.repeat(20) }), {}, /not the wrap order/);
  no(server(), { sellToken: '0x' + '7b'.repeat(20) }, /not the wrap order/);
  no(server(), { account: R_RELAYER }, /not the wrap order/);
  no(undefined, {}, /not the wrap order/);
  no(evm.tradeOrderTypedData({ token: R_AT.contract, chainId: R_AT.chainId, chainUid: R_AT.chainUid, order: { from: R_ME, nonce: 5 } }), {},
    /not the wrap order/);
  const away = { ...order, destination: '0x' + '66'.repeat(20), relayer: ZERO };
  assert.deepEqual(checkWrapOrder(server({ destination: away.destination, relayer: ZERO }), { ...want, order: away }).warnings,
    ['someone else receives the proceeds', 'any submitter may settle this order and earn the relayer share']);
  // the UA twin: ids, and its own struct
  const id = '0x' + '77'.repeat(32);
  const uaOrder = { ...order, destination: id };
  const ua = evm.uaWrapOrderTypedData({ ...R_AT, message: { ...uaOrder, from: id, nonce: 5 } });
  assert.deepEqual(checkUAWrapOrder(ua, { ...want, account: id, order: uaOrder }).warnings, []);
  assert.throws(() => checkWrapOrder(ua, { ...want, account: id, order: uaOrder }), /not the wrap order/);
  assert.throws(() => checkUAWrapOrder(server(), want), /not the wrap order/);
});

test('checkOp refuses a wrap order: its rules cannot be bypassed; the cancel of one still goes through checkCancel', () => {
  for (const [op, build] of [['WrapOrder', evm.wrapOrderTypedData], ['UAWrapOrder', evm.uaWrapOrderTypedData]]) {
    const td = build({ ...R_AT, message: {} });
    assert.throws(() => checkOp(td, { op, contract: R_AT.contract, chainId: R_AT.chainId, chainUid: R_AT.chainUid, message: td.message }),
      /Refusing to sign: .*checkWrapOrder/);
  }
});

test('until C6 the chain takes a wrap as a TradeOrder: that branch of checkTradeOrder and its cancel stay', () => {
  const order = { receiveToken: R_WRAPPER, amount: 1000, receiveAmount: 990, minFill: 1000, fee: 3000, relayer: R_RELAYER, dex: R_WRAPPER,
    flags: 1, batch: 1, validUntil: R_NOW + 600 };
  const td = evm.tradeOrderTypedData({ token: R_AT.contract, chainId: R_AT.chainId, chainUid: R_AT.chainUid, order: { ...order, from: R_ME, nonce: 5 } });
  checkTradeOrder(td, { account: R_ME, chainId: R_AT.chainId, chainUid: R_AT.chainUid, order, sellToken: R_AT.contract, wrappers: [R_WRAPPER], now: R_NOW });
  const cancel = evm.cancelOrderTypedData({ ...R_AT, message: { order: td.message } });
  assert.equal(hex(checkCancel(cancel, { account: R_ME, chainId: R_AT.chainId, chainUid: R_AT.chainUid, contract: R_AT.contract, order: td.message })),
    hex(hashTypedData(cancel)));
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
  const payment = { from: R_ME, to: R_RELAYER, value: 5, entryRef: '0x' + '09'.repeat(32), batch: 1, nonce: 0, validUntil: 9, mode: 0, relayer: R_RELAYER,
    fee: 0, feeRecipient: ZERO };
  const rf = { payment, fee: 1, feeRecipient: R_FEE_TO, validUntil: 9 };
  assert.throws(() => checkOp(evm.receiverFeeTypedData({ ...R_AT, message: rf }), rWant(rf, { op: 'ReceiverFee' })), /relayer you named is not bound/);
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
  const toUA = evm.wrapToUATypedData({ ...R_AT, message: { from: R_ME, amount: 1, underlying: R_WRAPPER, validUntil: R_NOW + 60 } });
  assert.throws(() => checkOp(toUA, rWant({ from: R_ME, amount: 1, underlying: R_WRAPPER }, { op: 'WrapToUA' })), miss);
  const zero = evm.cancelOrderTypedData({ ...R_AT, message: {} });
  assert.throws(() => checkOp(zero, rWant(undefined, { op: 'CancelOrder' })), /Refusing to sign/);
  assert.throws(() => checkOp(zero, rWant({}, { op: 'CancelOrder' })), miss);
  assert.throws(() => checkOp(zero, rWant({ order: {} }, { op: 'CancelOrder' })), miss);
  assert.throws(() => checkOp(zero, rWant({ order: { ...zero.message.order, flags: undefined } }, { op: 'CancelOrder' })), miss);
  // arrays and nested structs too; the whole struct passes; `{op}` alone says Refusing, not a TypeError
  const batch = evm.OP_BUILDERS.rollOverBatchTypedData({ ...R_AT, name: 'SCaaS ZetherToken', message: { from: R_ME, uas: [], validUntil: R_NOW + 60 } });
  assert.throws(() => checkOp(batch, rWant({ from: R_ME }, { op: 'RollOverBatch' })), miss);
  checkOp(zero, rWant(zero.message, { op: 'CancelOrder' }));
  assert.throws(() => checkOp(rUnwrap(), { op: 'Unwrap', contract: R_AT.contract }), /Refusing to sign/);
  assert.throws(() => checkOp(rUnwrap(), { op: 'Unwrap', contract: R_AT.contract, message: null }), /Refusing to sign/);
  // the empty string is no number
  assert.throws(() => evm.burnTypedData({ ...R_AT, message: { amount: '' } }), /Refusing to sign/);
  assert.throws(() => evm.burnTypedData({ ...R_AT, message: { amount: '   ' } }), /Refusing to sign/);
  assert.throws(() => checkOp(rUnwrap(), rWant({ ...R_OP, minOut: '' })), /Refusing to sign/);
  assert.throws(() => word(''), /not a number/);
  assert.throws(() => abiEncode(['uint256'], ['']), /not a number/);
  assert.equal(evm.burnTypedData({ ...R_AT, message: { amount: '0x10' } }).message.amount, '16');
  assert.equal(evm.burnTypedData({ ...R_AT, message: { amount: 16n } }).message.amount, '16');
});

test('a bool is true or false: \'false\' is no truth, in the builder, the hash or the calldata', () => {
  assert.throws(() => evm.setPayeeTypedData({ ...R_AT, name: 'SCaaS MandateWallet', message: { allowed: 'false' } }), /Refusing to sign: .*bool/);
  assert.throws(() => evm.setPayeeTypedData({ ...R_AT, name: 'SCaaS MandateWallet', message: { allowed: 1 } }), /Refusing to sign: .*bool/);
  assert.throws(() => zether.pqzAuthTypedData({ ...R_AT, name: 'SCaaS PqzToken', message: { auditorOn: 'false' } }), /Refusing to sign: .*bool/);
  assert.equal(evm.setPayeeTypedData({ ...R_AT, name: 'SCaaS MandateWallet', message: { allowed: false } }).message.allowed, false);
  assert.equal(evm.setPayeeTypedData({ ...R_AT, name: 'SCaaS MandateWallet', message: {} }).message.allowed, false);
  const types = { T: [{ name: 'ok', type: 'bool' }] };
  assert.throws(() => hashStruct(types, 'T', { ok: 'false' }), /bool/);
  assert.throws(() => abiEncode(['bool'], ['false']), /bool/);
  const td = evm.setPayeeTypedData({ ...R_AT, name: 'SCaaS MandateWallet', message: { allowed: true, validUntil: R_NOW + 60 } });
  td.message.allowed = 'false';
  assert.throws(() => checkOp(td, rWant({ from: ZERO, token: ZERO, payee: ZERO, allowed: true }, { op: 'SetPayee' })), /Refusing to sign/);
});

test('calldata refuses what the entry cannot verify: the missing signature, an encoded account blob; a shared op names its domain', () => {
  const row = (name) => V.ops[name];
  const one = (name) => Object.values(row(name).domains)[0];
  const tdOf = (name) => {
    const d = one(name);
    return builders[`${lower(name)}TypedData`]({ ...domainOf(row(name), d), message: row(name).message });
  };
  for (const name of ['PqzTransferSingle', 'UAPqzTransfer', 'PqzUnshield', 'PqzUnshieldUnwrap']) {
    assert.throws(() => builders[`${lower(name)}Calldata`](tdOf(name), one(name).signature), /Refusing to sign: pqzAuth is required/, name);
    assert.throws(() => builders[`${lower(name)}Calldata`](tdOf(name), one(name).signature, { pqzAuth: {} }), /pqzAuth is required/, name);
  }
  for (const name of ['RollOverSigned', 'UASetRollOverMode']) {
    assert.throws(() => builders[`${lower(name)}Calldata`](tdOf(name), one(name).signature), /Refusing to sign: ownerSig is required/, name);
  }
  assert.throws(() => evm.receiverFeeCalldata(tdOf('ReceiverFee'), one('ReceiverFee').signature), /payerSig is required/);
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
  assert.throws(() => evm.unwrapTypedData({ ...unnamed, message: {} }), /Refusing to sign: .*name/);
  assert.throws(() => evm.executeTypedData({ ...unnamed, message: {} }), /Refusing to sign: .*name/);
  assert.equal(evm.setPayeeTypedData({ ...unnamed, message: {} }).domain.name, 'SCaaS MandateWallet');
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
    assert.equal(run({ Unwrap: V.ops.Unwrap }).status, 0);
    const swapped = structuredClone(V.ops.Unwrap);
    const d = Object.values(swapped.domains)[0];
    const words = d.calldata.slice(10).match(/.{64}/g);
    [words[8], words[10]] = [words[10], words[8]]; // `wrapped` and `minOut`, after the eight envelope words
    d.calldata = d.calldata.slice(0, 10) + words.join('');
    const r = run({ Unwrap: swapped });
    assert.notEqual(r.status, 0);
    assert.match(r.stderr, /Unwrap token: calldata/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
