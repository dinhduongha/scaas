// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Headless check of rows.json without a wallet: ethers (the page's pinned build, downloaded by the caller) renders each
// row's typed data, exactly the JSON the page sends, to the row's digest; a throwaway key made at run time signs it with
// signTypedData and the signature recovers to that key over the row's digest; a negative control (one field changed) must not.
//   node docs/research/ua-mtx-merge-wallet-display/check.mjs <ethers.umd.min.js 6.13.4>
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const ethers = createRequire(import.meta.url)(process.argv[2] ?? (() => { throw new Error('give the ethers UMD path'); })());
const { chainId, rows } = JSON.parse(readFileSync(fileURLToPath(new URL('rows.json', import.meta.url)), 'utf8'));
const wallet = ethers.Wallet.createRandom();
let bad = 0;
const check = (ok, what) => { console.log(`${ok ? 'ok  ' : 'FAIL'} ${what}`); if (!ok) bad++; };

for (const row of rows) {
  const td = JSON.parse(JSON.stringify(row.typedData)); // what eth_signTypedData_v4 receives
  const types = Object.fromEntries(Object.entries(td.types).filter(([k]) => k !== 'EIP712Domain'));
  check(Number(td.domain.chainId) === chainId, `${row.id}: domain chainId ${td.domain.chainId}`);
  check(ethers.TypedDataEncoder.hash(td.domain, types, td.message) === row.digest, `${row.id}: ethers digest = ${row.digest}`);
  const sig = await wallet.signTypedData(td.domain, types, td.message);
  check(ethers.recoverAddress(row.digest, sig) === wallet.address, `${row.id}: signature recovers the throwaway key`);
  // negative control: the first bytes32 field (or the first field) changed by one bit
  const f = td.types[td.primaryType].find((x) => x.type === 'bytes32') ?? td.types[td.primaryType][0];
  const v = BigInt(td.message[f.name]) ^ 1n;
  const changed = { ...td.message, [f.name]: f.type === 'bytes32' ? ethers.toBeHex(v, 32) : v.toString() };
  const sig2 = await wallet.signTypedData(td.domain, types, changed);
  check(ethers.recoverAddress(row.digest, sig2) !== wallet.address, `${row.id}: ${f.name} changed, no match (negative control)`);
}
console.log(bad ? `${bad} FAIL` : `all ${rows.length} rows ok`);
process.exit(bad ? 1 : 0);
