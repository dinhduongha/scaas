// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// The ANS-104 cross-check both ways (chains-arweave plan T16; CLI-UAL-64): for every row of smartcontracts/vectors/arweave/
// items.json, the item the pinned arbundles (@dha-team/arbundles 1.2.0, this directory's lock file) builds from the same key,
// data, tags, target and anchor is byte-identical to ours, and arbundles' own `DataItem.verify` accepts ours; then items
// arbundles builds under other keys parse with clientkeys' verifying parser and their ids match. Outside clientkeys' tree:
//   cd clients/clientkeys/xcheck/arbundles && npm ci --ignore-scripts && node check.mjs
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import * as ar from "../../src/arweave.js";
import { fromHex, hex, keccak_256, utf8ToBytes } from "../../src/bytes.js";

const require = createRequire(import.meta.url);
const ab = require("@dha-team/arbundles");
const ed = require("@noble/ed25519");
const bs58 = require("bs58");
const V = JSON.parse(readFileSync(new URL("../../../../smartcontracts/vectors/arweave/items.json", import.meta.url), "utf8"));

/** arbundles' type-2 key (Curve25519 leaves the key and the public key to a subclass). */
class Ed25519Signer extends ab.Curve25519 {
  constructor(seed, pub) {
    super("", "");
    this.seed = Buffer.from(seed);
    this.pub = Buffer.from(pub);
  }
  get publicKey() {
    return this.pub;
  }
  get key() {
    return this.seed;
  }
}

async function signer(type, secret) {
  if (type === 3) return new ab.EthereumSigner(Buffer.from(secret).toString("hex"));
  const pub = await ed.getPublicKey(secret);
  if (type === 2) return new Ed25519Signer(secret, pub);
  return new ab.HexSolanaSigner(bs58.encode(Buffer.concat([Buffer.from(secret), Buffer.from(pub)])));
}

const text = (b) => Buffer.from(fromHex(b)).toString("utf8");
const opts = (r) => ({
  target: r.target ? Buffer.from(fromHex(r.target)).toString("base64url") : undefined,
  anchor: r.anchor ? text(r.anchor) : undefined,
  tags: r.tags.map((t) => ({ name: text(t.name), value: text(t.value) })),
});

let ok = 0;
let bad = 0;
const check = (cond, what) => {
  if (cond) ok++;
  else {
    bad++;
    console.log(`FAIL ${what}`);
  }
};

// (1) ours == arbundles', byte for byte; arbundles accepts ours
for (const r of V.items) {
  const s = await signer(r.type, fromHex(r.secret));
  const d = ab.createData(Buffer.from(fromHex(r.data)), s, opts(r));
  await d.sign(s);
  check(hex(d.getRaw()) === r.item, `${r.name}: arbundles builds another item`);
  check(d.id === r.id, `${r.name}: arbundles' id`);
  check(await ab.DataItem.verify(Buffer.from(fromHex(r.item))), `${r.name}: arbundles refuses ours`);
}
// (2) arbundles' items under other keys parse with ours, ids equal
for (const type of [2, 3, 4]) {
  for (const i of [0, 1, 2]) {
    const secret = keccak_256(utf8ToBytes(`scaas/arweave/xcheck/${type}/${i}`));
    const s = await signer(type, secret);
    const tags = i === 1 ? [{ name: "Content-Type", value: "application/octet-stream" }] : [];
    const d = ab.createData(Buffer.from(utf8ToBytes(`xcheck ${type} ${i}`)), s, { tags });
    await d.sign(s);
    let parsed = null;
    try {
      parsed = ar.parseItem(new Uint8Array(d.getRaw()));
    } catch (e) {
      console.log(`  ours refused arbundles' type ${type} item ${i}: ${e.code ?? e.message}`);
    }
    check(parsed && parsed.id === d.id, `arbundles type ${type} item ${i} parses with its id`);
  }
}
// (3) the refusal rows: how arbundles' own verify judges each (informative: ours is stricter by design, spec §7.2)
for (const r of V.refusals) {
  let v;
  try {
    v = await ab.DataItem.verify(Buffer.from(fromHex(r.item)));
  } catch {
    v = "throws";
  }
  console.log(`  refusal "${r.name}" (${r.code}): arbundles verify ${v}`);
}
console.log(`${ok} checks passed, ${bad} failed`);
process.exit(bad ? 1 : 0);
