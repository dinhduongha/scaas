// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Group 3f (PQZ verifier mode spec 2026-11-06-attested-verify §5, §11.3; ua-mtx-merge T46): the `PqzVerdict` a verifier UA
// signs in a PQZ token's domain under `pqz-verdict`, `statementHash` / `proofHash`, the empty verdict, the verdict last on the
// six signed PQZ entries (after `auth`, outside every `UA*` struct), and the router's three verifier ops. The type strings are
// read from the contract sources, apart from the table in src/evm.js; the digests from smartcontracts/vectors/pqz/verdict.json
// (forge-written, PqzVerdictVectors.t.sol). UNAUDITED.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import * as evm from '../src/evm.js';
import * as zether from '../src/zether.js';
import * as ua from '../src/ua.js';
import { hex, fromHex, keccak_256, utf8ToBytes } from '../src/bytes.js';

const ROOT = new URL('../../../', import.meta.url);
const read = (path) => readFileSync(new URL(path, ROOT), 'utf8');
const json = (path) => JSON.parse(read(path));
const V = json('smartcontracts/vectors/typed/typed_ops.json');
const PQZ = 'smartcontracts/vectors/pqz/';
const VERDICT_FILE = new URL(`${PQZ}verdict.json`, ROOT);
const ZERO = '0x' + '00'.repeat(20);
const Z32 = '0x' + '00'.repeat(32);
const k = (s) => hex(keccak_256(utf8ToBytes(s)));
/** A Solidity string constant `NAME = keccak256("…")` of a contract source, by name. */
const solString = (path, name) => {
  const m = new RegExp(`${name}\\s*=\\s*keccak256\\(\\s*"([^"]*)"\\s*\\)`).exec(read(path));
  assert.ok(m, `${name} in ${path}`);
  return m[1];
};
const UA_ENV = '(bytes32,uint256,uint256,uint256,uint32,address,uint256,address)';
const UA_SIG = '(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[])';
const SIGNED_VERDICT = `((address,uint256,bytes32,bytes32,bytes32,uint32,uint64),${UA_SIG})`;
const PQZ_ENTRIES = ['UAPqzTransferSingle', 'UAPqzTransferSingleCompact', 'UAPqzTransfer', 'UAPqzTransferCompact', 'UAPqzUnshield',
  'UAPqzUnshieldUnwrap'];
const at = { contract: '0x' + '7a'.repeat(20), chainId: 7622, chainUid: '0x' + 'c1'.repeat(32) };
const verdict = (o = {}) => ({ token: at.contract, chainId: at.chainId, proofSystemId: '0x' + '5e'.repeat(32), statementHash: '0x' + '51'.repeat(32),
  proofHash: '0x' + '9f'.repeat(32), pqzVerifierEpoch: 3, validUntil: 1800000900, ...o });

// --- the struct, the purpose, the empty verdict

test('PqzVerdict: the type string of PqzCore.sol, the purpose of UAKinds.sol, the token domain only', () => {
  const ts = solString('smartcontracts/evm/src/pqz/PqzCore.sol', 'VERDICT_TYPEHASH');
  assert.equal(ts, 'PqzVerdict(address token,uint256 chainId,bytes32 proofSystemId,bytes32 statementHash,bytes32 proofHash,'
    + 'uint32 pqzVerifierEpoch,uint64 validUntil)', 'spec §5.1');
  const td = evm.pqzVerdictTypedData({ ...at, message: verdict() });
  assert.equal(td.primaryType, 'PqzVerdict');
  assert.equal(evm.encodeType(td.types, 'PqzVerdict'), ts);
  assert.equal(evm.PQZ_VERDICT_TYPEHASH, k(ts));
  assert.deepEqual(td.domain, { name: 'SCaaS PqzToken', version: '1', chainId: '7622', verifyingContract: at.contract, salt: at.chainUid });
  const purpose = solString('smartcontracts/evm/src/ua/UAKinds.sol', 'PURPOSE_PQZ_VERDICT');
  assert.equal(purpose, 'scaas.ua.purpose.pqz-verdict.v1');
  assert.equal(hex(ua.PQZ_VERDICT_TAG), k(purpose));
  assert.equal(ua.isPortablePurpose(ua.PQZ_VERDICT_TAG), false, 'a native verifier signs UAAuth, never the typed digest itself');
  // the builders of the confidential module are the same functions
  assert.equal(zether.pqzVerdictTypedData, evm.pqzVerdictTypedData);
  assert.equal(zether.pqzVerdictDigest, evm.pqzVerdictDigest);
});

test('PqzVerdict: the digest by hand; every field signed; token and chainId must repeat the domain; ranges refused', () => {
  const m = verdict();
  const td = evm.pqzVerdictTypedData({ ...at, message: m });
  const w = (n) => hex(fromHex(BigInt(n).toString(16).padStart(64, '0')));
  const struct = keccak_256(fromHex(evm.PQZ_VERDICT_TYPEHASH + [w(BigInt(m.token)), w(m.chainId), m.proofSystemId, m.statementHash, m.proofHash,
    w(m.pqzVerifierEpoch), w(m.validUntil)].map((x) => x.slice(2)).join('')));
  assert.equal(hex(evm.hashStruct(td.types, 'PqzVerdict', td.message)), hex(struct));
  const digest = hex(evm.pqzVerdictDigest({ ...at, message: m }));
  assert.equal(digest, hex(evm.hashTypedData(td)));
  for (const [f, v] of Object.entries({ proofSystemId: Z32, statementHash: Z32, proofHash: Z32, pqzVerifierEpoch: 4, validUntil: 1800000901 })) {
    assert.notEqual(hex(evm.pqzVerdictDigest({ ...at, message: { ...m, [f]: v } })), digest, f);
  }
  assert.notEqual(hex(evm.pqzVerdictDigest({ ...at, contract: '0x' + '7b'.repeat(20), message: { ...m, token: '0x' + '7b'.repeat(20) } })), digest);
  assert.throws(() => evm.pqzVerdictTypedData({ ...at, message: { ...m, token: '0x' + '7b'.repeat(20) } }), /Refusing to sign: .*token/);
  assert.throws(() => evm.pqzVerdictTypedData({ ...at, message: { ...m, chainId: 1 } }), /Refusing to sign: .*chain/);
  assert.throws(() => evm.pqzVerdictTypedData({ ...at, message: { ...m, pqzVerifierEpoch: 2 ** 32 } }), /uint32/);
  assert.throws(() => evm.pqzVerdictTypedData({ ...at, message: { ...m, validUntil: 2n ** 64n } }), /uint64/);
  assert.throws(() => evm.pqzVerdictTypedData({ ...at, message: { ...m, ua: Z32 } }), /ua is not a field of PqzVerdict/);
});

test('the empty verdict: every field 0 and an empty UASig (spec §5.1)', () => {
  const e = evm.EMPTY_PQZ_VERDICT;
  assert.deepEqual(e, { pqzVerdict: { token: ZERO, chainId: '0', proofSystemId: Z32, statementHash: Z32, proofHash: Z32, pqzVerifierEpoch: 0,
    validUntil: '0' }, sig: { keyData: '0x', signature: '0x', members: [] } });
  assert.ok(Object.isFrozen(e) && Object.isFrozen(e.pqzVerdict) && Object.isFrozen(e.sig));
  assert.equal(zether.EMPTY_PQZ_VERDICT, e);
});

// --- statementHash / proofHash on the real statements and proofs of the build's set

/** The statement bytes `proof_pqzl.json`'s row names (`{file, form}`, `{file, case}` or `{file, disclosure}`). */
function statementOf(ref, files) {
  files[ref.file] ??= json(PQZ + ref.file);
  const s = files[ref.file];
  const key = ref.case ?? ref.disclosure;
  const hit = (ref.disclosure ? s.disclosures : s.rows).filter((x) => (key ? x.case === key : x.form === ref.form));
  assert.equal(hit.length, 1, JSON.stringify(ref));
  return hit[0].stmt;
}

test('statementHash / proofHash: keccak256 of the statement and proof bytes of every proof_pqzl.json row', () => {
  const P = json(PQZ + 'proof_pqzl.json');
  const files = {};
  let n = 0;
  for (const r of P.rows) {
    assert.equal(evm.statementHash(statementOf(r.statement, files)), `0x${r.stmt_keccak}`, r.form);
    assert.equal(evm.proofHash(`0x${r.proof}`), `0x${r.proof_keccak}`, r.form);
    assert.equal(evm.proofHash(fromHex(r.proof)), `0x${r.proof_keccak}`, `${r.form}: bytes or hex`);
    n++;
  }
  assert.ok(n > 10, `${n} rows`);
  assert.equal(evm.statementHash('0x'), k(''));
});

// --- the vector file (forge-written): every row reproduced, the signature recovers the verifier

test('verdict.json: domains, struct hashes, digests, the registry uaAuthDigest under pqz-verdict, the EOA verifier\'s signature',
  { skip: existsSync(VERDICT_FILE) ? false : 'verdict.json not written yet (PqzVerdictVectors.t.sol, WRITE_VERDICT_VECTORS=true)' }, () => {
    const F = JSON.parse(readFileSync(VERDICT_FILE, 'utf8'));
    // the build's set's proofs: vectors/pqz/ for n2048-kmax1024, else its <set>/ (PqzVerdictVectors.t.sol `_src`)
    const P = json(`${PQZ}${F.set === 'n2048-kmax1024' ? '' : `${F.set}/`}proof_pqzl.json`);
    assert.equal(F.typehash, evm.PQZ_VERDICT_TYPEHASH);
    assert.equal(F.typeString, solString('smartcontracts/evm/src/pqz/PqzCore.sol', 'VERDICT_TYPEHASH'));
    assert.equal(F.purposeTag, hex(ua.PQZ_VERDICT_TAG));
    assert.equal(F.proofSystemId, `0x${P.proof_system_id}`, 'the build\'s set');
    const { domain: D, registryDomain: G } = F;
    assert.equal(D.name, 'SCaaS PqzToken');
    const dom = { contract: D.verifyingContract, chainId: D.chainId, chainUid: D.salt };
    const reg = { generation: Number(G.version), chainId: G.chainId, registry: G.verifyingContract, chainUid: G.salt };
    assert.equal(G.name, 'SCaaS UARegistry');
    assert.equal(hex(ua.uaAuthDomainSeparator(reg)), G.separator);
    // the verifier: a native EOA, its id the address zero-padded
    const pub = secp256k1.getPublicKey(fromHex(BigInt(F.verifierKey).toString(16).padStart(64, '0')), false);
    assert.equal(F.verifierUA, evm.padId(hex(keccak_256(pub.subarray(1)).subarray(12))));
    const want = P.rows.filter((r) => r.form !== 'REGISTER');
    assert.equal(F.rows.length, want.length);
    F.rows.forEach((r, i) => {
      assert.equal(r.form, want[i].form, `row ${i}`);
      assert.deepEqual([r.statementHash, r.proofHash], [`0x${want[i].stmt_keccak}`, `0x${want[i].proof_keccak}`], `row ${i}: the proof file's hashes`);
      assert.equal(evm.proofHash(`0x${want[i].proof}`), r.proofHash, `row ${i}: proofHash of the proof's bytes`);
      const message = { token: D.verifyingContract, chainId: D.chainId, proofSystemId: F.proofSystemId, statementHash: r.statementHash,
        proofHash: r.proofHash, pqzVerifierEpoch: r.pqzVerifierEpoch, validUntil: r.validUntil };
      const td = evm.pqzVerdictTypedData({ ...dom, message });
      assert.equal(hex(evm.hashStruct(td.types, 'EIP712Domain', td.domain)), D.separator, `row ${i}`);
      assert.equal(hex(evm.hashStruct(td.types, 'PqzVerdict', td.message)), r.structHash, `row ${i}`);
      const digest = evm.pqzVerdictDigest({ ...dom, message });
      assert.equal(hex(digest), r.digest, `row ${i}`);
      const auth = ua.uaAuthDigest(reg, F.verifierUA, ua.PQZ_VERDICT_TAG, digest);
      assert.equal(hex(auth), r.uaAuthDigest, `row ${i}`);
      const sig = fromHex(r.signature);
      assert.equal(sig.length, 65, `row ${i}: 65-byte r ‖ s ‖ v`);
      const s = secp256k1.Signature.fromBytes(sig.subarray(0, 64), 'compact');
      assert.ok(!s.hasHighS(), `row ${i}: low-s`);
      assert.equal(hex(s.addRecoveryBit(sig[64] - 27).recoverPublicKey(auth).toBytes(false)), hex(pub), `row ${i}`);
    });
  });

// --- the six signed PQZ entries: the verdict after `auth`, unbound

test('the six signed PQZ entries take PqzSignedVerdict last, after auth; the rows carry the empty verdict', () => {
  for (const name of PQZ_ENTRIES) {
    for (const [kind, d] of Object.entries(V.ops[name].domains)) {
      assert.ok(d.abi.endsWith(`,bytes,${UA_SIG},${SIGNED_VERDICT})`), `${name} ${kind}: accHint, auth, the verdict`);
      assert.deepEqual(d.extra.pqzVerdict, evm.EMPTY_PQZ_VERDICT, `${name} ${kind}`);
    }
  }
  // the selectors of the contract's own signatures (IPqzToken / PqzLayer / WrappedPqzToken, spec §5.3)
  const PA = '(uint64,uint256,uint256,bytes32,uint64,bytes32,bytes32,bytes16,bytes,bytes,bytes,bytes,bytes)';
  const MA = '(uint64,uint256,uint256,bytes32,uint64,bytes32,uint256,bytes16,bytes[],(bytes32,bytes,bytes)[],bytes,bytes)';
  const BA = '(uint64,uint256,uint256,bytes32,uint64,bytes32,bytes,bytes)';
  const tail = `bytes,${UA_SIG},bytes,${UA_SIG},${SIGNED_VERDICT})`;
  const abiOf = (name) => Object.values(V.ops[name].domains)[0].abi;
  assert.equal(abiOf('UAPqzTransferSingle'), `mtxConfidentialTransferSingle(${UA_ENV},${PA},${tail}`);
  assert.equal(abiOf('UAPqzTransferSingleCompact'), `mtxConfidentialTransferSingleCompact(${UA_ENV},${PA},${tail}`);
  assert.equal(abiOf('UAPqzTransfer'), `mtxConfidentialTransfer(${UA_ENV},${MA},${tail}`);
  assert.equal(abiOf('UAPqzTransferCompact'), `mtxConfidentialTransferCompact(${UA_ENV},${MA},${tail}`);
  assert.equal(abiOf('UAPqzUnshield'), `mtxUnshield(${UA_ENV},${BA},(uint256,bytes32),${tail}`);
  assert.equal(abiOf('UAPqzUnshieldUnwrap'), `mtxUnshieldUnwrap(${UA_ENV},${BA},(address,bytes32,uint256,uint256),${tail}`);
});

/** The top-level parameter types of an ABI signature. */
function params(abi) {
  const out = [];
  let depth = 0;
  let start = abi.indexOf('(') + 1;
  for (let i = start; i < abi.length - 1; i++) {
    if (abi[i] === '(') depth++;
    else if (abi[i] === ')') depth--;
    else if (abi[i] === ',' && depth === 0) { out.push(abi.slice(start, i)); start = i + 1; }
  }
  out.push(abi.slice(start, -1));
  return out;
}

const dynamic = (t) => t === 'bytes' || t === 'string' || t.endsWith('[]') || (t[0] === '(' && params(t).some(dynamic));
/** The words a parameter takes in the head: a static tuple its members', anything else one. */
const headWords = (t) => (t[0] === '(' && !dynamic(t) ? params(t).reduce((n, m) => n + headWords(m), 0) : 1);

const rowTd = (name) => {
  const r = V.ops[name];
  const d = r.domains.pqz;
  return [d, zether[`${evm.TYPED_OPS[name].builder}TypedData`]({ name: d.domain.name, contract: d.domain.verifyingContract, chainId: d.domain.chainId,
    chainUid: d.domain.salt, message: r.message })];
};

test('the verdict is unbound: a relayer swapping it changes the calldata\'s tail only, never the signed digest', () => {
  for (const name of PQZ_ENTRIES) {
    const [d, td] = rowTd(name);
    const call = zether[`${evm.TYPED_OPS[name].builder}Calldata`];
    const empty = hex(call(td, d.signature, d.extra));
    assert.equal(empty, d.calldata, name);
    const signed = { pqzVerdict: verdict({ token: d.domain.verifyingContract, chainId: d.domain.chainId }), sig: '0x' + '5a'.repeat(65) };
    const full = hex(call(td, d.signature, { ...d.extra, pqzVerdict: signed }));
    assert.notEqual(full, empty, name);
    assert.equal(hex(evm.hashTypedData(td)), d.digest, `${name}: the digest is the verdict's neither way`);
    // the verdict is the last parameter: its tail starts where the last head word points, and every byte before it is unchanged
    const words = full.slice(10).match(/.{64}/g);
    const ps = params(d.abi);
    const head = ps.slice(0, -1).reduce((n, t) => n + headWords(t), 0); // a static tuple (UAEnvelope, Payout, Unwrap) sits inline
    const at0 = Number(BigInt(`0x${words[head]}`)) / 32;
    assert.equal(full.slice(0, 10 + 64 * at0), empty.slice(0, 10 + 64 * at0), `${name}: the signed parameters unchanged`);
    const w = (n) => BigInt(n).toString(16).padStart(64, '0');
    const pv = signed.pqzVerdict;
    assert.deepEqual(words.slice(at0, at0 + 7), [w(BigInt(pv.token)), w(pv.chainId), pv.proofSystemId.slice(2), pv.statementHash.slice(2),
      pv.proofHash.slice(2), w(pv.pqzVerifierEpoch), w(pv.validUntil)], `${name}: the verdict's fields in the struct's order`);
  }
});

test('the verdict is required on every signed PQZ entry; a half verdict is refused', () => {
  for (const name of PQZ_ENTRIES) {
    const [d, td] = rowTd(name);
    const call = zether[`${evm.TYPED_OPS[name].builder}Calldata`];
    const { pqzVerdict, ...noVerdict } = d.extra;
    assert.throws(() => call(td, d.signature, noVerdict), /Refusing to sign: the PQZ verdict is required/, name);
    assert.throws(() => call(td, d.signature, { ...noVerdict, pqzVerdict: { pqzVerdict: verdict() } }), /verdict signature is required/, name);
    assert.throws(() => call(td, d.signature, { ...noVerdict, pqzVerdict: { ...evm.EMPTY_PQZ_VERDICT, sig: '0x' + '5a'.repeat(65) } }),
      /an empty verdict carries no signature/, name);
    assert.throws(() => call(td, d.signature, { ...noVerdict, pqzVerdict: { pqzVerdict: verdict({ pqzVerifierEpoch: 2 ** 32 }), sig: '0x01' } }),
      /uint32/, name);
  }
});

// --- the router's three verifier ops (spec §4.2, §4.3)

const ROUTER_OPS = { UAPqzSetVerifier: ['UA_PQZ_SET_VERIFIER', 'next', 'mtxPqzSetVerifier', `address,bytes32`],
  UAPqzCancelVerifier: ['UA_PQZ_CANCEL_VERIFIER', '', 'mtxPqzCancelVerifier', 'address'],
  UAPqzRevokeVerifier: ['UA_PQZ_REVOKE_VERIFIER', '', 'mtxPqzRevokeVerifier', 'address'] };

test('the router\'s PQZ verifier ops: the type strings of GovernanceRouterBase.sol, target first, fee mode NONE, the router domain', () => {
  for (const [name, [constant, own, entry, args]] of Object.entries(ROUTER_OPS)) {
    const s = solString('smartcontracts/evm/src/governance/GovernanceRouterBase.sol', constant);
    const op = evm.TYPED_OPS[name];
    assert.ok(op, `${name}: no row`);
    assert.equal(op.typeString, s, name);
    assert.equal(op.typehash, k(s), name);
    assert.deepEqual(op.fields.map((f) => f.name).slice(0, -7), ['from', 'target', ...(own ? [own] : [])], name);
    assert.deepEqual([op.on, op.domains, op.envelope, op.ua, op.entry], [['GovernanceRouter'], ['SCaaS GovernanceRouter'], true, true, entry], name);
    const r = V.ops[name];
    assert.deepEqual(Object.keys(r.domains), ['gov_router'], name);
    assert.deepEqual([r.message.mode, r.message.fee], [1, '0'], `${name}: fee mode NONE`);
    assert.equal(r.domains.gov_router.abi, `${entry}(${UA_ENV},${args},${UA_SIG})`, name);
    assert.equal(r.domains.gov_router.extra, undefined, `${name}: takes nothing unsigned`);
  }
  const rs = read('smartcontracts/evm/src/governance/GovernanceRouter.sol');
  for (const [, , entry] of Object.values(ROUTER_OPS)) assert.match(rs, new RegExp(`function ${entry}\\(MetaTxLib\\.UAEnvelope calldata e, address target,`));
});

test('the router\'s PQZ verifier ops: a non-zero unbound relayer or feeRecipient signs as 0; target and next are signed', () => {
  const JUNK = '0x' + 'ba'.repeat(20);
  for (const name of Object.keys(ROUTER_OPS)) {
    const r = V.ops[name];
    const d = r.domains.gov_router;
    const where = { contract: d.domain.verifyingContract, chainId: d.domain.chainId, chainUid: d.domain.salt };
    const build = (m) => evm.OP_BUILDERS[`${evm.TYPED_OPS[name].builder}TypedData`]({ ...where, message: m });
    // the row's mode 1: the relayer bound, the fee recipient not; a non-zero one signs as 0
    const given = build({ ...r.message, feeRecipient: JUNK });
    assert.equal(given.message.feeRecipient, ZERO, name);
    assert.equal(hex(evm.hashTypedData(given)), d.digest, name);
    assert.notEqual(hex(evm.hashStruct(given.types, name, { ...r.message, feeRecipient: JUNK })), r.structHash, `${name}: canon matters`);
    // mode 0: both unbound, both non-zero, both signed as 0
    const open = build({ ...r.message, mode: 0, relayer: JUNK, feeRecipient: JUNK });
    assert.deepEqual([open.message.relayer, open.message.feeRecipient], [ZERO, ZERO], name);
    assert.equal(hex(evm.hashTypedData(open)), hex(evm.hashTypedData(build({ ...r.message, mode: 0, relayer: ZERO, feeRecipient: ZERO }))), name);
    assert.notEqual(hex(evm.hashTypedData(open)), d.digest, `${name}: the mode is signed`);
    assert.notEqual(hex(evm.hashTypedData(build({ ...r.message, target: JUNK }))), d.digest, `${name}: target is signed`);
  }
  const r = V.ops.UAPqzSetVerifier;
  const where = { contract: r.domains.gov_router.domain.verifyingContract, chainId: r.domains.gov_router.domain.chainId,
    chainUid: r.domains.gov_router.domain.salt };
  assert.notEqual(hex(evm.hashTypedData(evm.OP_BUILDERS.uaPqzSetVerifierTypedData({ ...where, message: { ...r.message, next: Z32 } }))),
    r.domains.gov_router.digest, 'next is signed');
});
