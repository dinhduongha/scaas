// smartcontracts/vectors/ua/metatx3.json (UA-4): the UA ledger's typed data. Each row's typed data hashes to its digest,
// the builders rebuild it from the message alone, the type strings give the pinned typehashes, and the native rows'
// signatures recover the native key of signatures.json (derived auth blobs are verified on chain by
// test/ua/UAMetaTx3Vectors.t.sol with the real verifiers).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { hex, fromHex, keccak_256, utf8ToBytes } from '../src/bytes.js';
import { hashTypedData, padId, uaMetaTxTypedData, uaMetaTransferTypedData } from '../src/evm.js';

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
