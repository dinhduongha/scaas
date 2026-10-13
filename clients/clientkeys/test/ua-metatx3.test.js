// smartcontracts/vectors/ua/metatx3.json (UA-4): the UA ledger's typed data. Each row's typed data hashes to its digest,
// the builders rebuild it from the message alone, the type strings give the pinned typehashes, and the native rows'
// signatures recover the native key of signatures.json (derived auth blobs are verified on chain by
// test/ua/UAMetaTx3Vectors.t.sol with the real verifiers).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { secp256k1, schnorr } from '@noble/curves/secp256k1.js';
import { p256 } from '@noble/curves/nist.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import * as ua from '../src/ua.js';
import { hex, fromHex, keccak_256, utf8ToBytes, abiEncode, concatBytes } from '../src/bytes.js';
import { hashTypedData, hashStruct, padId, uaMetaTxTypedData, uaMetaTransferTypedData, receiverFeeTypedData,
  unwrapToUACalldata } from '../src/evm.js';

const dir = new URL('../../../smartcontracts/vectors/ua/', import.meta.url);
const V = JSON.parse(readFileSync(new URL('metatx3.json', dir)));
const S = JSON.parse(readFileSync(new URL('signatures.json', dir)));
const domain = { name: 'SCaaS MetaToken', contract: V.token, chainId: V.chainId, chainUid: V.chainUid };

test('every row: typed data → digest, and the builder rebuilds the typed data from its message', () => {
  for (const [rows, build] of [[V.call, uaMetaTxTypedData], [V.transfer, uaMetaTransferTypedData]]) {
    assert.equal(rows.length, 9);
    for (const r of rows) {
      assert.equal(hex(hashTypedData(r.typedData)), r.digest, r.name);
      assert.deepEqual(build({ ...domain, message: r.typedData.message }), r.typedData, r.name);
      assert.equal(r.typedData.message.from, r.from);
    }
  }
});

test('typehashes and the signer set match signatures.json', () => {
  const th = (t) => hex(keccak_256(utf8ToBytes(t)));
  const fields = (td) => td.types[td.primaryType].map((f) => `${f.type} ${f.name}`).join(',');
  assert.equal(th(`UAMetaTransaction(${fields(V.call[0].typedData)})`), V.typeHashes.UAMetaTransaction);
  assert.equal(th(`UAMetaTransfer(${fields(V.transfer[0].typedData)})`), V.typeHashes.UAMetaTransfer);
  assert.deepEqual(V.call.slice(1).map((r) => r.from), S.derived.map((d) => d.ua));
  assert.equal(V.call[0].from, S.native.ua);
  assert.equal(padId(S.native.address), S.native.ua);
});

test('the native rows are ECDSA over the v3 digest itself (CTR-UA-24), not the UAAuth wrapper', () => {
  for (const r of [V.call[0], V.transfer[0]]) {
    const sig = fromHex(r.auth);
    assert.equal(sig.length, 65);
    const rec = secp256k1.Signature.fromBytes(sig.subarray(0, 64), 'compact').addRecoveryBit(sig[64] - 27);
    const pub = rec.recoverPublicKey(fromHex(r.digest)).toBytes(false);
    assert.equal(hex(keccak_256(pub.subarray(1)).subarray(12)), S.native.address);
  }
});

// --- UA-5a: burn, unwrapToUA, receiverFee (accounts.md CTR-UA-26/28, metatx.md CTR-MTX-05/06) ---
const recover = (sig, digest) => {
  const s = fromHex(sig);
  const rec = secp256k1.Signature.fromBytes(s.subarray(0, 64), 'compact').addRecoveryBit(s[64] - 27);
  return hex(keccak_256(rec.recoverPublicKey(fromHex(digest)).toBytes(false).subarray(1)).subarray(12));
};
/** abi.encode(bytes keyData, bytes sig) → [keyData, sig]. */
const split = (auth) => {
  const b = fromHex(auth);
  const at = (o) => Number(BigInt(hex(b.subarray(o, o + 32))));
  const bytesAt = (head) => { const o = at(head); return b.subarray(o + 32, o + 32 + at(o)); };
  return [bytesAt(0), bytesAt(32)];
};
/** The derived kinds noble verifies directly (the others: on chain, UAMetaTx3Vectors.t.sol with the real verifiers). */
const NOBLE = {
  0x0101: (kd, m, sig) => p256.verify(sig, sha256(m), concatBytes(Uint8Array.of(4), kd), { prehash: false, lowS: true }),
  0x0103: (kd, m, sig) => schnorr.verify(sig, m, kd),
  0x0102: (kd, m, sig) => ed25519.verify(sig, m, kd, { zip215: false }),
};
const authOk = (from, purpose, digest, auth) => {
  if (from === S.native.ua) return recover(auth, digest) === S.native.address;
  const d = S.derived.find((x) => x.ua === from);
  const [kd, sig] = split(auth);
  assert.equal(hex(kd), d.keyData);
  return NOBLE[d.kind] ? NOBLE[d.kind](kd, ua.uaMessage(d.kind, ua.purposeTag(purpose), fromHex(digest)), sig) : null;
};

test('burn and unwrapToUA rows: one per signer of call, the same envelope, data the new call', () => {
  const sel = (sig) => hex(keccak_256(utf8ToBytes(sig)).subarray(0, 4));
  const unwrapToUA = hex(unwrapToUACalldata('0x5ca00000000000000000000000000000000000b1', 1000000n,
    S.derived.find((d) => d.name === 'p256').ua, 990000n));
  for (const [rows, data, batch] of [[V.burn, sel('burn(uint256)') + '00'.repeat(29) + '0f4240', '8'],
    [V.unwrapToUA, unwrapToUA, '9']]) {
    assert.deepEqual(rows.map((r) => r.from), V.call.map((r) => r.from));
    for (const r of rows) {
      const m = r.typedData.message;
      assert.equal(m.data, data, r.name);
      assert.equal(m.batch, batch);
      assert.equal(hex(hashStruct(r.typedData.types, 'UAMetaTransaction', m)), r.structHash);
      assert.equal(hex(hashTypedData(r.typedData)), r.digest, r.name);
      assert.deepEqual(uaMetaTxTypedData({ ...domain, message: m }), r.typedData, r.name);
      assert.notEqual(authOk(r.from, 'metatx', r.digest, r.auth), false, r.name);
    }
  }
  assert.equal(hex(unwrapToUACalldata('0x5ca00000000000000000000000000000000000b1', 1000000n, '0x' + 'ab'.repeat(32), 990000n)),
    '0xe4a9f766' + '0'.repeat(24) + '5ca00000000000000000000000000000000000b1' + '0'.repeat(59) + 'f4240' + 'ab'.repeat(32)
    + '0'.repeat(59) + 'f1b30');
});

test('receiverFee rows: native payer x every derived payee and p256 x bip340; payer under metatx, payee under receiver-fee', () => {
  assert.deepEqual(V.receiverFee.map((r) => `${r.payer}>${r.payee}`),
    [...S.derived.map((d) => `native>${d.name}`), 'p256>bip340']);
  let nobled = 0;
  for (const r of V.receiverFee) {
    const t = r.transfer.message;
    assert.equal(hex(hashTypedData(r.transfer)), r.paymentDigest);
    assert.deepEqual(uaMetaTransferTypedData({ ...domain, message: t }), r.transfer);
    assert.deepEqual([t.mode, t.fee, t.nonce], [1, '0', '0'], 'CTR-MTX-06 shape: fee NONE, relayer bound, nonce 0');
    const rf = r.receiverFee.message;
    assert.equal(rf.paymentDigest, r.paymentDigest);
    assert.deepEqual(receiverFeeTypedData({ ...domain, ...rf }), r.receiverFee);
    assert.equal(hex(hashTypedData(r.receiverFee)), r.receiverFeeDigest);
    for (const [id, purpose, digest, auth] of [[t.from, 'metatx', r.paymentDigest, r.payerAuth],
      [t.to, 'receiver-fee', r.receiverFeeDigest, r.payeeAuth]]) {
      const v = authOk(id, purpose, digest, auth);
      assert.notEqual(v, false, `${r.payer}>${r.payee} ${purpose}`);
      if (v === true) nobled++;
      if (id !== S.native.ua && v === true) {   // the purpose binds: the same signature under the other purpose fails
        assert.equal(authOk(id, purpose === 'metatx' ? 'receiver-fee' : 'metatx', digest, auth), false);
      }
    }
  }
  assert.equal(nobled, 8 + 1 + 4, 'the native payer x8 (ECDSA), the p256 payer, the p256 / bip340 x2 / ed25519 payees');
});
