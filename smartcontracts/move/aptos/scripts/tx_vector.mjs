// Pins the lane transaction of `meta::relay_pay` with the official TS SDK (@aptos-labs/ts-sdk, see package.json):
// BCS RawTransaction, the lane's signing message, SignedTransaction and the transaction hash. The Rust adapter test
// (adapters/aptos.rs `tx_matches_the_ts_sdk`) builds the same transaction from the cross vector and must match.
//   cd chains/aptos/scripts && npm ci && node tx_vector.mjs
import {
  Account, AccountAddress, ChainId, EntryFunction, MoveVector, RawTransaction, SimpleTransaction,
  TransactionPayloadEntryFunction, U128, U64, generateSignedTransaction, generateSigningMessageForTransaction,
  generateUserTransactionHash, Hex,
} from '@aptos-labs/ts-sdk';
import { readFileSync } from 'node:fs';

const vectors = readFileSync(new URL('../tests/vectors.move', import.meta.url), 'utf8');
const blob = Hex.fromHexString(vectors.match(/a_pay_eur_0 signature blob = ([0-9a-f]+)/)[1]).toUint8Array();
const fn = (name) => vectors.match(new RegExp(`public fun ${name}\\(\\)[^{]*\\{ ([^}]+) \\}`))[1].trim();
const hexOf = (s) => s.replace(/^x"|"$/g, '');
const addrOf = (s) => s.replace(/^@/, '');
const lane0 = Account.fromDerivationPath({ path: "m/44'/637'/0'/0'/0'", mnemonic: 'abandon '.repeat(23) + 'art' });
const u8 = (h) => MoveVector.U8(Hex.fromHexString(h).toUint8Array());
const args = [
  AccountAddress.from(addrOf(fn('alice'))), AccountAddress.from(addrOf(fn('eur'))), AccountAddress.from('0x' + 'beef'.padStart(64, '0')),
  new U128(100n), u8('01'.repeat(32)), u8('a1'.repeat(32)), new U64(0n), new U64(1000n), AccountAddress.ZERO,
  u8('00'.repeat(32)), u8(hexOf(fn('alice_pk'))), MoveVector.U8(blob.slice(0, 64)), MoveVector.U8(blob.slice(64)),
];
const payload = new TransactionPayloadEntryFunction(EntryFunction.build(`0x${'b0b'.padStart(64, '0')}::meta`, 'relay_pay', [], args));
const raw = new RawTransaction(lane0.accountAddress, 7n, payload, 200000n, 100n, 1700000000n, new ChainId(4));
const transaction = new SimpleTransaction(raw);
const senderAuthenticator = lane0.signTransactionWithAuthenticator(transaction);
console.log(JSON.stringify({
  sdk: JSON.parse(readFileSync(new URL('./node_modules/@aptos-labs/ts-sdk/package.json', import.meta.url))).version,
  lane0: lane0.accountAddress.toStringLong(),
  raw: Hex.fromHexInput(raw.bcsToBytes()).toStringWithoutPrefix(),
  signing_message: Hex.fromHexInput(generateSigningMessageForTransaction(transaction)).toStringWithoutPrefix(),
  signed: Hex.fromHexInput(generateSignedTransaction({ transaction, senderAuthenticator })).toStringWithoutPrefix(),
  hash: generateUserTransactionHash({ transaction, senderAuthenticator }),
}, null, 1));
