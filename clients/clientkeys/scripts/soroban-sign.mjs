// The UA-Soroban e2e signer (plan SOR-D13): the vector signers of scripts/soroban-ua-ops-vectors.mjs, so the e2e signs
// exactly as ua-ops.json does. Test keys only (fixed secrets, deterministic signatures).
//   node scripts/soroban-sign.mjs <kind> <keyIndex> <hex digest> <purpose>
//     kind: webauthn-p256 | p256 | ed25519 | secp256k1 | mldsa44 | mldsa65 | msig (the 2-of-3; keyIndex ignored)
//     purpose: metatx | trade | metatx-cancel | member | pop (= the portable pop v2: digest = registrationDigest)
//   → {"ua": "0x…", "keyData": "0x…", "auth": "0x…"}
import { hex, fromHex } from '../src/bytes.js';
import { signer, authFor } from './soroban-ua-ops-vectors.mjs';

const [kind, index, digest, purpose] = process.argv.slice(2);
if (!purpose || !/^\d+$/.test(index) || !/^(0x)?[0-9a-fA-F]{64}$/.test(digest)) {
  console.error('usage: soroban-sign.mjs <kind> <keyIndex> <hex digest (32 bytes)> <purpose>');
  process.exit(2);
}
const sg = signer(kind, ...(kind === 'msig' ? [] : [Number(index)]));
const { auth } = authFor(sg, purpose, fromHex(digest));
console.log(JSON.stringify({ ua: hex(sg.ua), keyData: hex(sg.keyData), auth: hex(auth) }));
