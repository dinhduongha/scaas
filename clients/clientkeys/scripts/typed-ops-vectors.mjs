// Generates smartcontracts/vectors/typed/typed_ops.json (typed-signing C1): one row per signed struct of the table in
// src/evm.js, for every reproducer (Review Focus 2) and the contract tests of C2-C6: type string, typehash, the JSON a wallet
// signs (`types`, `message`), struct hash and, per domain kind, the domain, digest, a native ECDSA signature (secret of
// signatures.json's `native` key, RFC 6979), the entry's signature, selector and calldata. Fields a row does not set are
// fillers, keccak256 of the field's path: right types, not valid proofs, ciphertexts or lengths, since a typed digest
// hashes `bytes` whatever their length. C2-C6 run these against the chain as NamedEntry.t.sol does (`structHash` under the
// contract's own domain). The rows of the C0 entries and of C6's orders, cancels and receiver fees take values their
// fixtures accept. ua-mtx-merge T11 (CTR-MTX-30, MD-7): one row per op, the merged `UA<Op>` on its `mtx<Op>` entry with
// `UASig`; the address rows of merged ops are in vectors/typed/legacy/ua-mtx-merge/ (generator in clientkeys/legacy/).
//   node scripts/typed-ops-vectors.mjs [outDir]
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { hex, fromHex, keccak_256, utf8ToBytes, concatBytes } from '../src/bytes.js';
import { TYPED_OPS, OP_BUILDERS, hashStruct, hashTypedData, uaMetaTransferTypedData, padId, payLane, buildRelayFee, payMeta, payNoFromUuid, metaPayId,
  EMPTY_PQZ_VERDICT,
} from '../src/evm.js';
import { confPublic, g1 } from '../src/zether.js';
import { recordId } from '../src/regulated.js';
import { releaseApprovalKey } from '../src/factory.js';
import { ecdsa, nativeSk, nativeAddr, nativeUa, be } from './ua-signers.mjs';

const VECTORS = fileURLToPath(new URL('../../../smartcontracts/vectors/', import.meta.url));
const OUT = process.argv[2] ?? join(VECTORS, 'typed');
const { contexts } = JSON.parse(readFileSync(join(VECTORS, 'ua/structures.json'), 'utf8'));

const KIND = { 'SCaaS MetaToken': 'token', 'SCaaS ZetherToken': 'zether', 'SCaaS PqzToken': 'pqz', 'SCaaS MandateWallet': 'wallet',
  'SCaaS SmartKeyAccount': 'account', 'SCaaS Dex': 'dex', 'SCaaS GovernanceRouter': 'gov_router' };
const CONTRACT = { token: '0x5ca00000000000000000000000000000000000a1', zether: '0x5ca00000000000000000000000000000000000a2',
  pqz: '0x5ca00000000000000000000000000000000000a3', wallet: '0x5ca00000000000000000000000000000000000a4',
  account: '0x5ca00000000000000000000000000000000000a5', dex: '0x5ca00000000000000000000000000000000000a6',
  gov_router: '0x5ca00000000000000000000000000000000000a7' };
const FROM = hex(nativeAddr);
const RELAYER = '0x000000000000000000000000000000000000beef';
const FEE_TO = '0x0000000000000000000000000000000000000fee';
const ROUTER = '0x5ca00000000000000000000000000000000000e0';
const EXECUTOR = '0x5ca00000000000000000000000000000000000e1';
const TARGET = '0x5ca00000000000000000000000000000000000c0';
const VALID_UNTIL = 1800000300;
const NONE = '0x' + '00'.repeat(20);
const NO_ID = '0x' + '00'.repeat(32);
const WRAPPER = '0x5ca00000000000000000000000000000000000b2';
const BUYS = '0x5ca00000000000000000000000000000000000b3';
const BUYS_ON = '0x5ca00000000000000000000000000000000000b4';
const SELLS = '0x5ca00000000000000000000000000000000000b5';
const hash = (path) => keccak_256(utf8ToBytes(`scaas.typed-ops.${path}`));
const filler = (path, n) => hex(concatBytes(hash(path), hash(`${path}.1`), hash(`${path}.2`), hash(`${path}.3`), hash(`${path}.4`)).subarray(0, n));

/** A filler of `type`, a field path through the struct `types`. */
function fill(type, path, types) {
  if (type.endsWith('[]')) return [0, 1].map((i) => fill(type.slice(0, -2), `${path}.${i}`, types));
  if (types[type]) return Object.fromEntries(types[type].map((f) => [f.name, fill(f.type, `${path}.${f.name}`, types)]));
  if (type === 'bool') return true;
  if (type === 'address') return hex(hash(path).subarray(12));
  if (type === 'bytes') return filler(path, 64);
  if (type === 'bytes32') return hex(hash(path));
  if (type.startsWith('bytes')) return hex(hash(path).subarray(0, Number(type.slice(5))));
  const n = BigInt(hex(hash(path).subarray(0, 3))) % 251n + 1n;
  return Number(type.slice(4)) <= 32 ? Number(n) : String(n * 1000n);
}

// The values a row sets. A wallet, an account or the router takes fee NONE; PERCENT only on an AMOUNT op (CTR-MTX-20).
const envelope = (op) => {
  const noFee = ['MandateWallet', 'SmartKeyAccount', 'GovernanceRouter'].some((c) => op.on.includes(c));
  const [mode, fee] = noFee ? [1, 0] : op.amount ? [0x13, 5000] : [0x23, 1000];
  return { batch: 7, nonce: 0, validUntil: VALID_UNTIL, mode, relayer: RELAYER, fee, feeRecipient: noFee ? '0x' + '00'.repeat(20) : FEE_TO };
};
const ZETHER_UA = confPublic('bls12381', 0xb0bn).UA; // `bob` of ZetherFixture
// pay-meta-tax T41: every pay row's `entryRef` is the commitment of one `PayMeta` (its `extra.meta`, the entry's last parameter);
// plan T83: `payNo` a right-aligned UUIDv7, `save` on
const META = payMeta({ salt: hex(hash('paymeta.salt')), payNo: payNoFromUuid('019a6e3c-5f00-7a3b-8c4d-5e6f708192a3'), save: true });
const META_ID = metaPayId(META);
const pay = (id, to) => {
  const entryRef = META_ID;
  return { from: id, to, value: 100000000, entryRef, batch: payLane(entryRef), nonce: 0, validUntil: VALID_UNTIL, mode: 1, relayer: RELAYER,
    fee: 0, feeRecipient: NONE };
};
// An order the chain takes: `order` buys `BUYS` on `dex`; `wrapOrder` is the same terms minted by `WRAPPER` (TS-D19).
const TERMS = { amount: 1000, minFill: 1000, fee: 3000, relayer: RELAYER, flags: 0, batch: 7, nonce: 1, validUntil: VALID_UNTIL };
const order = (from, destination, dex = BUYS_ON) => ({ ...TERMS, from, receiveToken: BUYS, receiveAmount: 2000, dex, destination });
const wrapOrder = (from, destination) => ({ ...TERMS, from, wrappedToken: WRAPPER, minMinted: 1000, destination });
const COMMIT_REVEAL = { sealedMemo: '0x' };  // a BUNDLE form carries no memo
const ROW = {
  UAUnwrap: { wrapped: 1000000, minOut: 990000, recipient: '0x0000000000000000000000000000000000000B0B' },
  UAShield: { toUA: ZETHER_UA, amount: 10 },
  // the delegate a 32-byte id (Q6, CTR-ACC-12), the address of today's row zero-padded
  UASetMandate: { token: '0x5ca00000000000000000000000000000000000b1', delegate: padId('0x00000000000000000000000000000000000000d2'),
    maxPerPayment: 7, maxPerPeriod: 9, periodSeconds: 86400, expiry: 1900000000 },
  AddKey: { kind: 2 },
  RotateKey: { kind: 2 },
  UASetRollOverMode: { rollOverMode: 1 },
  ZetherSetRollOverMode: { mode: 1 },
  PqzAuth: { op: 1, chainId: contexts.A.chainId, token: CONTRACT.pqz, registry: contexts.A.registry, chainUid: contexts.A.chainUid },
  UAReceiverFee: { payment: pay(hex(nativeUa), padId('0x0000000000000000000000000000000000005409')), fee: 300000, feeRecipient: FEE_TO,
    validUntil: 1800000060 },
  // a regulated kind's payment with its tax (pay-meta-tax spec §5.2): AMOUNT 1,000 of the 100,000,000
  UAPayWithTax: { payment: pay(hex(nativeUa), padId('0x0000000000000000000000000000000000005409')), taxMode: 2, tax: 1000 },
  UAPayUnderMandate: { entryRef: META_ID },
  UASetTaxRate: { ratePpm: 50000 },
  UASetTaxRecipient: { taxRecipient: padId('0x00000000000000000000000000000000000007a0') },
  // group 3f (T46): a native EOA as the next verifier (no registration needed, spec §4.1)
  UAPqzSetVerifier: { next: padId('0x5ca00000000000000000000000000000000000f1') },
  // group 3h (T61): LOG
  UASetProofStore: { next: 1 },
  // round 3t (CTR-PQZ-36): the verifier fee 3; relayer and fee recipient unbound (mode 0), as MetaTxLib.canon hashes them
  UASetVerifierFee: { next: 3, mode: 0, fee: 0 },
  // group 3l (wrap limits spec §6, §9): one leg at a hundredth of a 6-decimal unit, a daily wrap window, the net rule with a
  // two-year decay; values a hybrid at `target` with bits 25 and 26 takes (TypedOps.t.sol's router rows); a member both ways
  UASetWrapLimits: { legs: [{ underlying: '0x5ca00000000000000000000000000000000000c3', unitExp: 4, decayDays: 730,
    wrapShort: { perUser: 100000, tokenWide: 0, period: 86400 }, wrapLong: { perUser: 0, tokenWide: 5000000, period: 2592000 },
    unwrapShort: { perUser: 0, tokenWide: 0, period: 0 }, unwrapLong: { perUser: 0, tokenWide: 0, period: 0 } }],
    netUnwrap: true, wrapList: false, unwrapList: false },
  UASetWrapMember: { account: padId('0x00000000000000000000000000000000000007a1'), canWrap: true, canUnwrap: true },
};
ROW.UAWrapOrder = wrapOrder(hex(nativeUa), NO_ID);
ROW.CancelUAOrder = { order: order(hex(nativeUa), NO_ID) };
ROW.CancelUAWrapOrder = { order: ROW.UAWrapOrder };
ROW.CancelDexOrder = { order: { sellToken: SELLS, order: order(FROM, NONE, CONTRACT.dex) } };
// The router's rows (governance T12) take values a real token, wrapped token and DEX accept: bit 1 (`MINTABLE`), terms a
// holder may get, a rate step inside 10 %. The rest are fillers.
for (const n of ['GrantRole', 'RevokeRole', 'SetGrant', 'CancelGrant', 'DisableFeature', 'RenounceRole']) ROW[`UA${n}`] = { bit: 1 };
ROW.UASetGrant.terms = { min: 2, max: 50, total: 1000, perWindow: 100, window: 86400, validUntil: 1900000000, maxUses: 7, delegable: true,
  scope: NO_ID };
ROW.UAProposeRate = { num: 101, den: 100 };
ROW.UAPqzTransferSingle = { args: COMMIT_REVEAL };
// Group 3h (pqz-proof-path spec §3.2, plan T59): the six PQZ debit rows carry `ownTag` (a filler: the contract checks no value),
// are tagged `"release": "3h"` (C9) and leave the relayer and the fee recipient unbound at fee 0 (mode 0: fee NONE, no restriction
// bit; every mtx* write is relayable at fee 0): the message holds 0 for both, as `MetaTxLib.canon` hashes them, and
// test/typed-ops.test.js signs each row again with a non-zero value in both (a reproducer that forgets the canon fails there).
const RELEASE_3H = new Set(['UAPqzTransferSingle', 'UAPqzTransferSingleCompact', 'UAPqzTransfer', 'UAPqzTransferCompact', 'UAPqzUnshield',
  'UAPqzUnshieldUnwrap']);
for (const n of RELEASE_3H) ROW[n] = { ...ROW[n], mode: 0, fee: 0 };
// The regulated controls (regulated-kinds spec §3.1, ua-mtx-merge T34): values a kind-8 token at `target` takes at
// REG_NOW (TypedOps.t.sol's regulated rows): one record runs through them, recorded by `UARecordOrder`, backing `UAFreeze`,
// moved under by `UAForceTransfer`, ended by `UARevokeOrder`; `UAOperatorTransfer` moves the record's subject's units.
const REG_NOW = 1800000000;
const DAY = 86400;
const REG_REF = hex(hash('regulated.ref'));
const ORDER = { orderId: hex(hash('regulated.order')), documentHash: hex(hash('regulated.document')),
  subject: padId('0x5ca00000000000000000000000000000000000c1'), beneficiary: padId('0x5ca00000000000000000000000000000000000c2'),
  maxAmount: 1000, freezeUntil: REG_NOW + 90 * DAY };
const RECORD = recordId(ORDER.orderId, ORDER.subject, ORDER.beneficiary);
ROW.UARecordOrder = ORDER;
ROW.UAFreeze = { account: ORDER.subject, ref: REG_REF, recordId: RECORD };
ROW.UAUnfreeze = { account: ORDER.subject, ref: REG_REF };
ROW.UAForceTransfer = { recordId: RECORD, amount: 30 };
ROW.UAPause = { ref: REG_REF, until: REG_NOW + 3 * DAY };
ROW.UAUnpause = { ref: REG_REF };
ROW.UARevokeOrder = { recordId: RECORD, reasonRef: hex(hash('regulated.reason')) };
ROW.UAOperatorTransfer = { account: ORDER.subject, to: ORDER.beneficiary, amount: 5, ref: REG_REF };
// The factory's creations (ua-mtx-merge T76): the init bytes are fillers (the router passes them through; the factory's
// release decodes them), `initHash` their keccak256, a class-4 instance.
const INIT_ARGS = filler('create.initArgs', 96);
const INIT_CALL = filler('create.initCall', 68);
ROW.UACreateToken = { kind: 0, version: 1, initHash: hex(keccak_256(fromHex(INIT_ARGS))), salt: hex(hash('create.token.salt')) };
ROW.UACreateDex = { version: 1, initHash: hex(keccak_256(fromHex(INIT_ARGS))), salt: hex(hash('create.dex.salt')) };
ROW.UACreateInstance = { contractClass: 4, kind: 0, version: 1, initHash: hex(keccak_256(fromHex(INIT_CALL))),
  salt: hex(hash('create.instance.salt')) };

// Round 3r (spec 2026-11-10-admin-not-owner.md §5.4): the admin ops of the factory and a compliance registry. The token kinds
// are `NORMAL` (an enum on the entry: a filler would not decode); `UAApproveTokenRelease` leaves the relayer and the fee
// recipient unbound at fee 0 (mode 0): 0 in the message, as `MetaTxLib.canon` hashes them, and test/typed-ops.test.js signs it
// again with a non-zero value in both. Every other field is a filler (the router signs and forwards; the target checks).
const REASON = 'a release found bad';
ROW.UAPublishTokenEnv = { kind: 0 };
ROW.UAApproveTokenRelease = { kind: 0, mode: 0, fee: 0 };
ROW.UADeprecateToken = { kind: 0, reason: REASON };
ROW.UADeprecateDex = { reason: REASON };
ROW.UADeprecateRelease = { reason: REASON };
ROW.UASetTokenKindEnabled = { kind: 1, on: true };

function sample(name, op) {
  const own = {};
  for (const f of op.fields) own[f.name] = fill(f.type, `${name}.${f.name}`, op.types);
  const base = op.envelope ? { ...own, ...envelope(op), from: op.ua ? hex(nativeUa) : FROM } : own;
  const row = ROW[name] ?? {};
  const merged = { ...base, ...row };
  for (const k of Object.keys(row)) {
    if (row[k] && typeof row[k] === 'object' && !Array.isArray(row[k])) merged[k] = { ...base[k], ...row[k] }; // an array is the row's
  }
  return merged;
}

// A row of the UA-signed extras: a `pqzAuth` in the msig shape, a Zether owner's `ownerSig` (Schnorr, 160 B).
// Slot 0 an `msig` member with its list (spec 2026-11-02-msig-nested), slot 2 a signing member.
const PQZ_AUTH = { keyData: '0x', signature: '0x', members: [
  { index: 0, members: [{ index: 0, sig: filler('pqzAuth.0.0', 65) }, { index: 1, sig: filler('pqzAuth.0.1', 65) }], sig: '0x' },
  { index: 2, members: [], sig: filler('pqzAuth.2', 65) }] };
const OWNER_SIG = { keyData: '0x', signature: filler('ownerSig', 160), members: [] };
const nativeSig = (digest) => hex(ecdsa(nativeSk, digest));

function extraOf(name, td, at) {
  // group 3g: a per-kind row (`UAPqzRollOver`) by its struct (`UARollOver`): the rollover takes no `pqzAuth`. Group 3f (T46):
  // the six PQZ entries take the verdict last, the empty one here (a PRECOMPILE token); the router's `UAPqz*Verifier` neither.
  const base = (TYPED_OPS[name]?.primary ?? name).replace(/^UA/, '');
  if (/^Pqz(Transfer|Unshield)/.test(base)) return { pqzAuth: PQZ_AUTH, pqzVerdict: EMPTY_PQZ_VERDICT };
  if (base === 'RollOverSigned' || base === 'SetRollOverMode') return { ownerSig: OWNER_SIG };
  if (base === 'ReceiverFee') {
    return { payerSig: nativeSig(hashTypedData(uaMetaTransferTypedData({ ...at, message: td.message.payment }))), meta: META };
  }
  if (base === 'PayWithTax' || base === 'PayUnderMandate') return { meta: META };
  if (base === 'CreateToken' || base === 'CreateDex') return { initArgs: INIT_ARGS };
  if (base === 'CreateInstance') return { initCall: INIT_CALL };
  return undefined;
}

const ops = {};
for (const [name, op] of Object.entries(TYPED_OPS)) {
  // a per-kind row of one struct name (group 3g: `UAPqzRollOver`) names its EIP-712 primary type
  const row = { ...(op.primary !== name ? { primaryType: op.primary } : {}), ...(RELEASE_3H.has(name) ? { release: '3h' } : {}),
    typeString: op.typeString, typehash: op.typehash, on: op.on, types: op.types, domains: {} };
  const message = sample(name, op);
  const relay = name === 'UARelayFee' ? { token: CONTRACT.token, chainId: contexts.A.chainId, chainUid: contexts.A.chainUid, router: ROUTER,
    executor: EXECUTOR, target: TARGET, from: hex(nativeUa), amount: 25, batch: 7, nonce: 0, validUntil: VALID_UNTIL } : null;
  const callData = filler('relayed.call', 100);
  for (const dn of op.domains) {
    const kind = KIND[dn];
    const at = { name: dn, contract: CONTRACT[kind], chainId: contexts.A.chainId, chainUid: contexts.A.chainUid };
    const plan = relay && buildRelayFee({ ...relay, name: dn, token: CONTRACT[kind] }).payment(callData);
    const td = plan ? plan.typedData : OP_BUILDERS[`${op.builder}TypedData`]({ ...at, message });
    row.message = td.message;
    row.structHash = hex(hashStruct(td.types, op.primary, td.message));
    const digest = hashTypedData(td);
    const signature = nativeSig(digest);
    const extra = extraOf(name, td, at);
    const d = { domain: td.domain, domainSeparator: hex(hashStruct(td.types, 'EIP712Domain', td.domain)), digest: hex(digest), signature };
    if (op.call) {
      const { abi, data } = op.call(td, signature, extra);
      Object.assign(d, { abi, selector: hex(keccak_256(utf8ToBytes(abi)).subarray(0, 4)), calldata: hex(data) });
      if (extra) d.extra = extra;
    }
    if (plan) Object.assign(d, { router: ROUTER, relayedCall: callData, relayRef: plan.ref, lane: String(plan.lane),
      routerCalldata: hex(plan.calldata(signature)) });
    row.domains[kind] = d;
  }
  // round 3r (spec §5.6): the factory's key of the approved release, checked on the factory by FactoryAdmin.t.sol
  const domain = { UAApproveTokenRelease: 'token', UAApproveDexRelease: 'dex', UAApproveRelease: 'class' }[name];
  if (domain) row.approvalKey = releaseApprovalKey(domain, row.message);
  ops[name] = row;
}

const out = {
  note: 'Generated by clients/clientkeys/scripts/typed-ops-vectors.mjs (src/evm.js, @noble/curves 2.4.0); never edit by hand. '
    + 'typed-signing C1: one row per signed struct. `structHash` is domain-free; `domains.<kind>` per contract kind '
    + '(`token` SCaaS MetaToken, `zether` SCaaS ZetherToken, `pqz` SCaaS PqzToken, `wallet` SCaaS MandateWallet, `account` '
    + 'SCaaS SmartKeyAccount, `dex` SCaaS Dex, `gov_router` SCaaS GovernanceRouter) on context A of structures.json. `signature` is a native ECDSA over `digest` by '
    + '`key`; `calldata` is the entry with it: `UASig{signature}` (empty keyData and members) on every merged `mtx*` entry '
    + '(`UA*` rows, ua-mtx-merge CTR-MTX-30: one signed entry per operation; the address rows of merged ops are in '
    + 'vectors/typed/legacy/ua-mtx-merge/), `bytes` on the address entries left (the five wraps, `SmartKeyAccount`), '
    + '`AccountSig{0, [], signature}` on the account\'s own entries. An unbound `relayer` / `feeRecipient` is 0 in the message, '
    + 'as the contract hashes it. Field values not set by the generator are fillers (keccak256 of the field path), not valid '
    + 'proofs or ciphertexts. `extra`: what the entry takes unsigned (`meta`: the `PayMeta` a pay entry takes last, pay-meta-tax T41; '
    + '`pqzVerdict`: the `PqzSignedVerdict` a PQZ entry takes last, after the signature, the empty one of a PRECOMPILE token, group 3f). '
    + '`release: "3h"` (group 3h, pqz-proof-path spec §9.3, C9): a row of a format 3h moved (the six PQZ debits gain `ownTag`); those rows '
    + 'leave the relayer and the fee recipient unbound at fee 0 (mode 0), 0 in the message and the calldata.',
  version: 1, context: 'A', key: { private: hex(be(nativeSk, 32)), address: FROM, ua: hex(nativeUa) }, ops,
};
mkdirSync(OUT, { recursive: true });
writeFileSync(join(OUT, 'typed_ops.json'), JSON.stringify(out, null, 2) + '\n');
