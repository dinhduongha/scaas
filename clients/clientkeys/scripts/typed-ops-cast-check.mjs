// typed-signing C1: typed_ops.json against Foundry (alloy), no code of src/ involved: for every row and domain `cast wallet
// sign --data` over the wallet's JSON gives the row's signature (RFC 6979, so the same digest); `cast calldata-decode` gives the
// row's message, field by field and in the entry's order (scripts/typed-ops-expected.mjs), so a swapped parameter fails; and
// `cast calldata` over the decoded values gives the row's calldata back byte for byte. Needs `cast` on PATH.
//   node scripts/typed-ops-cast-check.mjs [typed_ops.json]
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { expectedCall, norm } from './typed-ops-expected.mjs';

const file = process.argv[2] ?? new URL('../../../smartcontracts/vectors/typed/typed_ops.json', import.meta.url);
const V = JSON.parse(readFileSync(file));
const cast = (...args) => execFileSync('cast', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 1 << 26 }).trim();
const dir = mkdtempSync(join(tmpdir(), 'typed-ops-'));

function members(t) {
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
/** A decoded value in the syntax `cast calldata` reads: tuples `(…)`, arrays `[…]`. */
function arg(t, v) {
  if (t.endsWith('[]')) return `[${v.map((x) => arg(t.slice(0, -2), x)).join(',')}]`;
  if (t.startsWith('(')) return `(${members(t).map((m, i) => arg(m, v[i])).join(',')})`;
  return String(v);
}
let signed = 0;
let encoded = 0;
try {
  for (const [name, r] of Object.entries(V.ops)) {
    for (const [kind, d] of Object.entries(r.domains)) {
      const json = join(dir, 'td.json');
      // group 3g: a per-kind row (`UAPqzRollOver`) names its primary type
      writeFileSync(json, JSON.stringify({ types: r.types, primaryType: r.primaryType ?? name, domain: d.domain, message: r.message }));
      const sig = cast('wallet', 'sign', '--private-key', V.key.private, '--data', '--from-file', json);
      if (sig !== d.signature) throw new Error(`${name} ${kind}: cast signs ${sig}, row ${d.signature}`);
      signed++;
      if (!d.abi) continue;
      const { data } = JSON.parse(cast('calldata-decode', '--json', d.abi, d.calldata));
      if (JSON.stringify(norm(data)) !== JSON.stringify(norm(expectedCall(name, r, d)))) {
        throw new Error(`${name} ${kind}: calldata decodes to ${JSON.stringify(data)}, not the row's message`);
      }
      const types = members(d.abi.slice(d.abi.indexOf('(')));
      const again = cast('calldata', d.abi, ...types.map((t, i) => arg(t, data[i])));
      if (again !== d.calldata) throw new Error(`${name} ${kind}: cast re-encodes ${again}, row ${d.calldata}`);
      encoded++;
    }
  }
} finally {
  rmSync(dir, { recursive: true, force: true });
}
console.log(`typed_ops.json: ${Object.keys(V.ops).length} structs, ${signed} digests and ${encoded} calldatas equal to cast's`);
