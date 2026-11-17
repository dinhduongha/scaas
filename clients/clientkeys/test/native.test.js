// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// ua-rs-native (spec 2026-11-17-ua-rs-native): the four native networks of an app's native backend (CLI-SGN-52), beside the nine
// of NETWORKS. Known answers are the published ones re-read at plan T0 (clients/ua-rs/runs/2026-11-17-ua-rs-native-t0.md):
// BIP-84 / BIP-86 (`abandon ×11 about`), BIP-143 native P2WPKH, BIP-341 wallet-test-vectors.json (scriptPubKey[0] and
// keyPathSpending input 0, the rows with a null scriptTree / merkleRoot), bitcoin/bips c1a652c7.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { schnorr } from '@noble/curves/secp256k1.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { base58 } from '@scure/base';
import * as S from '../src/seed.js';
import * as signer from '../src/seed-signer.js';
import * as U from '../src/uakey.js';
import { fromHex, hex } from '../src/bytes.js';

const B = (h) => fromHex(h.startsWith('0x') ? h : '0x' + h);
const H = (b) => hex(b).slice(2);
const codeOf = (f) => { try { f(); return null; } catch (e) { return e.code ?? `plain: ${e.message}`; } };
const ABANDON = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const seed = S.seedFromWords(ABANDON);
const NINE = ['evm', 'cosmos', 'hedera_ecdsa', 'hedera_ed25519', 'sui', 'stellar', 'ton', 'aptos', 'solana'];
const FOUR = ['bitcoin_p2wpkh', 'bitcoin_p2tr', 'near', 'polkadot'];

test('NETWORKS stays the nine; NATIVE_NETWORKS is the four, exported by seed-signer too', () => {
  assert.deepEqual(Object.keys(S.NETWORKS), NINE);
  assert.deepEqual(Object.keys(S.NATIVE_NETWORKS), FOUR);
  assert.equal(signer.NATIVE_NETWORKS, S.NATIVE_NETWORKS);
});

test('BIP-84 receive and change addresses of abandon ×11 about', () => {
  const k = (i, change) => S.deriveKey(seed, 'bitcoin_p2wpkh', i, { change });
  assert.equal(k(0).path, "m/84'/0'/0'/0/0");
  assert.equal(k(0).publicKey, '0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c');
  assert.equal(k(0).address, 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu');
  assert.equal(k(1).address, 'bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g');
  assert.equal(k(0, 1).path, "m/84'/0'/0'/1/0");
  assert.equal(k(0, 1).address, 'bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el');
  assert.deepEqual(k(0).witnessProgram, { version: 0, program: 'c0cebcd6c3d3ca8c75dc5ec62ebe55330ef910e2' });
  assert.notEqual(k(1, 1).address, k(0, 1).address);
  assert.equal(k(0, 0).address, k(0).address);
});

test('BIP-86 receive and change addresses, internal key, tweak and output key', () => {
  const k = (i, change) => S.deriveKey(seed, 'bitcoin_p2tr', i, { change });
  const r0 = k(0);
  assert.equal(r0.path, "m/86'/0'/0'/0/0");
  assert.equal(r0.internalKey, 'cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115');
  assert.equal(r0.outputKey, 'a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c');
  assert.equal(r0.address, 'bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr');
  assert.deepEqual(r0.witnessProgram, { version: 1, program: r0.outputKey });
  assert.equal(r0.publicKey.slice(2), r0.internalKey, 'publicKey is the compressed internal key P');
  assert.equal(k(1).address, 'bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh');
  const c0 = k(0, 1);
  assert.equal(c0.path, "m/86'/0'/0'/1/0");
  assert.equal(c0.internalKey, '399f1b2f4393f29a18c937859c5dd8a77350103157eb880f02e8c08214277cef');
  assert.equal(c0.outputKey, '882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc');
  assert.equal(c0.address, 'bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7');
  assert.notEqual(k(1, 1).address, c0.address);
});

test('BIP-341 scriptPubKey[0] (null scriptTree): taprootTweak gives tweak, output key and address', () => {
  const t = S.taprootTweak(B('d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d'));
  assert.equal(H(t.tweak), 'b86e7be8f39bab32a6f2c0443abbc210f0edac0e2c53d501b36b64437d9c6c70');
  assert.equal(H(t.outputKey), '53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343');
  assert.equal(S.segwitAddress('bc', 1, t.outputKey), 'bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5');
});

test('Bitcoin coin type: 1 gives tb1…, 0 is the default, 2 refused; change 2 refused; change off Bitcoin refused', () => {
  const t = S.deriveKey(seed, 'bitcoin_p2wpkh', 0, { coinType: 1 });
  assert.equal(t.path, "m/84'/1'/0'/0/0");
  assert.match(t.address, /^tb1q/);
  assert.match(S.deriveKey(seed, 'bitcoin_p2tr', 0, { coinType: 1 }).address, /^tb1p/);
  assert.equal(S.deriveKey(seed, 'bitcoin_p2wpkh', 0, { coinType: 0 }).address, 'bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu');
  assert.equal(codeOf(() => S.deriveKey(seed, 'bitcoin_p2wpkh', 0, { coinType: 2 })), 'Argument');
  assert.equal(codeOf(() => S.deriveKey(seed, 'bitcoin_p2tr', 0, { coinType: 2 })), 'Argument');
  assert.equal(codeOf(() => S.deriveKey(seed, 'bitcoin_p2wpkh', 0, { change: 2 })), 'Argument');
  assert.equal(codeOf(() => S.deriveKey(seed, 'bitcoin_p2wpkh', 0, { change: 1 })), null);
  assert.equal(codeOf(() => S.deriveKey(seed, 'evm', 0, { change: 1 })), 'Argument');
  assert.equal(codeOf(() => S.deriveKey(seed, 'near', 0, { change: 0 })), 'Argument');
  assert.equal(codeOf(() => S.deriveKey(seed, 'evm', 0)), null);
});

test('NEAR: m/44\'/397\'/i\', implicit account id, ed25519:base58 text; no coin-type override', () => {
  const k = S.deriveKey(seed, 'near', 0);
  assert.equal(k.path, "m/44'/397'/0'");
  assert.equal(S.deriveKey(seed, 'near', 3).path, "m/44'/397'/3'");
  assert.equal(k.address, k.publicKey);
  assert.match(k.address, /^[0-9a-f]{64}$/);
  assert.equal(k.publicKeyText, 'ed25519:' + base58.encode(B(k.publicKey)));
  assert.equal(H(ed25519.getPublicKey(k.privateKey)), k.publicKey);
  for (const c of [148, 397, 0]) assert.equal(codeOf(() => S.deriveKey(seed, 'near', 0, { coinType: c })), 'Argument', `coin ${c}`);
  assert.equal(codeOf(() => S.deriveKey(seed, 'stellar', 0, { coinType: 397 })), null, 'stellar keeps its override');
});

test('polkadot is not derived by deriveKey (it needs the entropy and the passphrase)', () => {
  assert.throws(() => S.deriveKey(seed, 'polkadot', 0), (e) => e.code === 'Argument' && /polkadotKey/.test(e.message));
});

test('BIP-143 native P2WPKH: signDigest is RFC 6979 with no extra data, r ‖ s ‖ v', () => {
  const key = { network: 'bitcoin_p2wpkh', curve: 'secp256k1', privateKey: B('619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9') };
  const sig = S.signDigest(key, B('c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670'), { allowRawDigest: true });
  assert.equal(H(sig.subarray(0, 32)), '3609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a');
  assert.equal(H(sig.subarray(32, 64)), '573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee');
  assert.ok(sig[64] === 27 || sig[64] === 28);
});

test('BIP-341 keyPathSpending input 0: signDigest on a P2TR key (negate, tweak, BIP-340, aux zero) and verify under x(Q)', () => {
  const key = { network: 'bitcoin_p2tr', curve: 'secp256k1', privateKey: B('6b973d88838f27366ed61c9ad6367663045cb456e28335c109e30717ae0c6baa') };
  const d = B('2514a6272f85cfa0f45eb907fcb0d121b808ed37c6ea160a5a9046ed5526d555');
  const sig = S.signDigest(key, d, { allowRawDigest: true, aux: new Uint8Array(32) });
  assert.equal(H(sig), 'ed7c1647cb97379e76892be0cacff57ec4a7102aa24296ca39af7541246d8ff14d38958d4cc1e2e478e4d4a764bbfd835b16d4e314b72937b29833060b87276c');
  assert.ok(schnorr.verify(sig, d, B('53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343')));
  // without aux: fresh randomness, still a valid signature under x(Q)
  const a = S.signDigest(key, d, { allowRawDigest: true }), b = S.signDigest(key, d, { allowRawDigest: true });
  assert.notEqual(H(a), H(b));
  assert.ok(schnorr.verify(a, d, B('53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343')));
});

test('P2TR keys of the mnemonic sign under their own output key, both y parities of P', () => {
  // receive 0 has an odd-y internal key, receive 1 an even one (T0)
  for (const i of [0, 1]) {
    const k = S.deriveKey(seed, 'bitcoin_p2tr', i);
    const d = new Uint8Array(32).fill(7 + i);
    assert.ok(schnorr.verify(S.signDigest(k, d, { allowRawDigest: true }), d, B(k.outputKey)), `index ${i}`);
  }
});

test('Bitcoin and NEAR keys: no key proof, no EIP-712, no EVM transaction (Argument); evm and solana keep theirs', () => {
  const tx = { type: 2, chainId: 1, nonce: 0, maxPriorityFeePerGas: 1, maxFeePerGas: 2, gasLimit: 21000, to: '0x' + '11'.repeat(20), value: 0, data: '0x', accessList: [] };
  const td = { types: { EIP712Domain: [{ name: 'name', type: 'string' }], M: [{ name: 'x', type: 'uint256' }] }, primaryType: 'M', domain: { name: 'n' }, message: { x: 1 } };
  for (const n of ['bitcoin_p2wpkh', 'bitcoin_p2tr', 'near']) {
    const k = S.deriveKey(seed, n, 0);
    assert.equal(codeOf(() => S.signKeyProof(k, new Uint8Array(32))), 'Argument', `${n} key proof`);
    assert.equal(codeOf(() => S.signTyped(k, td)), 'Argument', `${n} typed`);
    assert.equal(codeOf(() => S.signTransaction(k, tx)), 'Argument', `${n} transaction`);
  }
  const evm = S.deriveKey(seed, 'evm', 0);
  assert.equal(S.signTyped(evm, td).length, 65);
  assert.equal(S.signKeyProof(evm, new Uint8Array(32)).length, 65);
  assert.ok(S.signTransaction(evm, tx).raw);
  assert.equal(S.signKeyProof(S.deriveKey(seed, 'solana', 0), new Uint8Array(32)).length, 64);
});

test('no import and no imported UA of the four networks (Argument); evm accepted', () => {
  const secret = new Uint8Array(32).fill(1);
  for (const n of FOUR) {
    assert.equal(codeOf(() => S.importKey(n, secret)), 'Argument', `importKey ${n}`);
    for (const kind of [0x0108, 0x0102]) assert.equal(codeOf(() => U.importedUAKey({ network: n, secret, kind })), 'Argument', `importedUAKey ${n} ${kind}`);
  }
  assert.equal(S.importKey('evm', secret).network, 'evm');
  assert.ok(U.importedUAKey({ network: 'evm', secret, kind: 0x0108 }).ua);
});
