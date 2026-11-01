// Generates smartcontracts/vectors/typed/typed_ops.json (typed-signing C1): one row per signed struct of the table in
// src/evm.js, for every reproducer (Review Focus 2) and the contract tests of C2-C6: type string, typehash, the JSON a wallet
// signs (`types`, `message`), struct hash and, per domain kind, the domain, digest, a native ECDSA signature (secret of
// signatures.json's `native` key, RFC 6979), the entry's signature, selector and calldata. Fields a row does not set are
// fillers, keccak256 of the field's path: right types, not valid proofs, ciphertexts or lengths, since a typed digest
// hashes `bytes` whatever their length. C2-C6 run these against the chain as NamedEntry.t.sol does (`structHash` under the
// contract's own domain). The rows of the C0 entries take values their fixtures accept.
//   node scripts/typed-ops-vectors.mjs [outDir]
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { hex, fromHex, keccak_256, utf8ToBytes, concatBytes } from '../src/bytes.js';
import { TYPED_OPS, OP_BUILDERS, hashStruct, hashTypedData, metaTransferTypedData, uaMetaTransferTypedData, padId, payLane,
  buildRelayFee } from '../src/evm.js';
import { confPublic, g1 } from '../src/zether.js';
import { ecdsa, nativeSk, nativeAddr, nativeUa, be } from './ua-signers.mjs';

const VECTORS = fileURLToPath(new URL('../../../smartcontracts/vectors/', import.meta.url));
const OUT = process.argv[2] ?? join(VECTORS, 'typed');
const { contexts } = JSON.parse(readFileSync(join(VECTORS, 'ua/structures.json'), 'utf8'));

const KIND = { 'SCaaS MetaToken': 'token', 'SCaaS ZetherToken': 'zether', 'SCaaS PqzToken': 'pqz', 'SCaaS MandateWallet': 'wallet',
  'SCaaS SmartKeyAccount': 'account', 'SCaaS Dex': 'dex' };
const CONTRACT = { token: '0x5ca00000000000000000000000000000000000a1', zether: '0x5ca00000000000000000000000000000000000a2',
  pqz: '0x5ca00000000000000000000000000000000000a3', wallet: '0x5ca00000000000000000000000000000000000a4',
  account: '0x5ca00000000000000000000000000000000000a5', dex: '0x5ca00000000000000000000000000000000000a6' };
const FROM = hex(nativeAddr);
const RELAYER = '0x000000000000000000000000000000000000beef';
const FEE_TO = '0x0000000000000000000000000000000000000fee';
const ROUTER = '0x5ca00000000000000000000000000000000000e0';
const EXECUTOR = '0x5ca00000000000000000000000000000000000e1';
const TARGET = '0x5ca00000000000000000000000000000000000c0';
const VALID_UNTIL = 1800000300;
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

// The values a row sets. A wallet or an account takes fee NONE; PERCENT only on an AMOUNT op (CTR-MTX-20).
const envelope = (op) => {
  const noFee = op.on.includes('MandateWallet') || op.on.includes('SmartKeyAccount');
  const [mode, fee] = noFee ? [1, 0] : op.amount ? [0x13, 5000] : [0x23, 1000];
  return { batch: 7, nonce: 0, validUntil: VALID_UNTIL, mode, relayer: RELAYER, fee, feeRecipient: noFee ? '0x' + '00'.repeat(20) : FEE_TO };
};
const ZETHER_UA = confPublic('bls12381', 0xb0bn).UA; // `bob` of ZetherFixture
const pay = (id, to) => {
  const entryRef = hex(hash('payment'));
  return { from: id, to, value: 100000000, entryRef, batch: payLane(entryRef), nonce: 0, validUntil: VALID_UNTIL, mode: 1, relayer: RELAYER };
};
const COMMIT_REVEAL = { sealedMemo: '0x' };  // a BUNDLE form carries no memo
const ROW = {
  Unwrap: { wrapped: 1000000, minOut: 990000, recipient: '0x0000000000000000000000000000000000000B0B' },
  Shield: { toUA: ZETHER_UA, amount: 10 },
  SetMandate: { token: '0x5ca00000000000000000000000000000000000b1', delegate: '0x00000000000000000000000000000000000000d2',
    maxPerPayment: 7, maxPerPeriod: 9, periodSeconds: 86400, expiry: 1900000000 },
  AddKey: { kind: 2 },
  RotateKey: { kind: 2 },
  SetRollOverMode: { rollOverMode: 1 },
  ZetherSetRollOverMode: { mode: 1 },
  PqzAuth: { op: 1, chainId: contexts.A.chainId, token: CONTRACT.pqz, registry: contexts.A.registry, chainUid: contexts.A.chainUid },
  ReceiverFee: { payment: pay(FROM, '0x0000000000000000000000000000000000005409'), fee: 300000, feeRecipient: FEE_TO, validUntil: 1800000060 },
  UAReceiverFee: { payment: pay(hex(nativeUa), padId('0x0000000000000000000000000000000000005409')), fee: 300000, feeRecipient: FEE_TO,
    validUntil: 1800000060 },
};
ROW.UAShield = ROW.Shield;
ROW.UAUnwrap = ROW.Unwrap;
ROW.UASetRollOverMode = ROW.SetRollOverMode;
for (const t of ['PqzTransferSingle', 'UAPqzTransferSingle']) ROW[t] = { args: COMMIT_REVEAL };

function sample(name, op) {
  const own = {};
  for (const f of op.fields) own[f.name] = fill(f.type, `${name}.${f.name}`, op.types);
  const base = op.envelope ? { ...own, ...envelope(op), from: op.ua ? hex(nativeUa) : FROM } : own;
  const row = ROW[name] ?? {};
  const merged = { ...base, ...row };
  for (const k of Object.keys(row)) {
    if (row[k] && typeof row[k] === 'object') merged[k] = { ...base[k], ...row[k] };
  }
  return merged;
}

// A row of the UA-signed extras: a `pqzAuth` in the msig shape, a Zether owner's `ownerSig` (Schnorr, 160 B).
const PQZ_AUTH = { keyData: '0x', signature: '0x', members: [{ index: 0, keyData: '0x', sig: filler('pqzAuth.0', 65) },
  { index: 2, keyData: '0x', sig: filler('pqzAuth.2', 65) }] };
const OWNER_SIG = { keyData: '0x', signature: filler('ownerSig', 160), members: [] };
const nativeSig = (digest) => hex(ecdsa(nativeSk, digest));

function extraOf(name, td, at) {
  const base = name.replace(/^UA/, '');
  if (base.startsWith('Pqz') && base !== 'PqzAuth') return { pqzAuth: PQZ_AUTH };
  if (base === 'RollOverSigned' || base === 'SetRollOverMode') return { ownerSig: OWNER_SIG };
  if (base === 'ReceiverFee') {
    const build = name === 'ReceiverFee' ? metaTransferTypedData : uaMetaTransferTypedData;
    return { payerSig: nativeSig(hashTypedData(build({ ...at, message: td.message.payment }))) };
  }
  return undefined;
}

const ops = {};
for (const [name, op] of Object.entries(TYPED_OPS)) {
  const lower = name.replace(/^UA/, 'ua').replace(/^[A-Z]/, (c) => c.toLowerCase());
  const row = { typeString: op.typeString, typehash: op.typehash, on: op.on, types: op.types, domains: {} };
  const message = sample(name, op);
  const relay = name.endsWith('RelayFee') ? { token: CONTRACT.token, chainId: contexts.A.chainId, chainUid: contexts.A.chainUid, router: ROUTER,
    executor: EXECUTOR, target: TARGET, from: name === 'RelayFee' ? FROM : hex(nativeUa), amount: 25, validUntil: VALID_UNTIL,
    ua: name !== 'RelayFee' } : null;
  const callData = filler('relayed.call', 100);
  for (const dn of op.domains) {
    const kind = KIND[dn];
    const at = { name: dn, contract: CONTRACT[kind], chainId: contexts.A.chainId, chainUid: contexts.A.chainUid };
    const plan = relay && buildRelayFee({ ...relay, name: dn, token: CONTRACT[kind] }).payment(callData);
    const td = plan ? plan.typedData : OP_BUILDERS[`${lower}TypedData`]({ ...at, message });
    row.message = td.message;
    row.structHash = hex(hashStruct(td.types, name, td.message));
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
  ops[name] = row;
}

const out = {
  note: 'Generated by clients/clientkeys/scripts/typed-ops-vectors.mjs (src/evm.js, @noble/curves 2.4.0); never edit by hand. '
    + 'typed-signing C1: one row per signed struct. `structHash` is domain-free; `domains.<kind>` per contract kind '
    + '(`token` SCaaS MetaToken, `zether` SCaaS ZetherToken, `pqz` SCaaS PqzToken, `wallet` SCaaS MandateWallet, `account` '
    + 'SCaaS SmartKeyAccount, `dex` SCaaS Dex) on context A of structures.json. `signature` is a native ECDSA over `digest` by '
    + '`key`; `calldata` is the entry with it: `bytes`, `UASig{signature}` on `ua*`, `AccountSig{0, [], signature}` on the '
    + 'account\'s own entries. Field values not set by the generator are fillers (keccak256 of the field path), not valid '
    + 'proofs or ciphertexts. `extra`: what the entry takes unsigned.',
  version: 1, context: 'A', key: { private: hex(be(nativeSk, 32)), address: FROM, ua: hex(nativeUa) }, ops,
};
mkdirSync(OUT, { recursive: true });
writeFileSync(join(OUT, 'typed_ops.json'), JSON.stringify(out, null, 2) + '\n');
