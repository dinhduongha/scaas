// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// scaas-sdk plan T2b: the keystore container (src/keystore.js; scaas-sdk spec §6.1) against smartcontracts/vectors/keystore/
// keystore.json: every valid row parses and re-serialises to its bytes; every refused row is refused with its name, its base
// (one rule fixed) parses; random mutations of valid rows are refused only by name; the generator reproduces the file.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { shake256 } from "@noble/hashes/sha3.js";
import { parse, serialize, depthOf } from "../src/keystore.js";
import { indexMac } from "../src/keystore-mac.js";
import { openSeedVault } from "../src/vault.js";
import { utf8ToBytes } from "../src/bytes.js";

const DIR = fileURLToPath(new URL("../../../smartcontracts/vectors/keystore/", import.meta.url));
const K = JSON.parse(readFileSync(join(DIR, "keystore.json"), "utf8"));
const codeOf = (text) => {
  try {
    parse(text);
    return "ok";
  } catch (e) {
    return e.code ?? `unnamed: ${e.message}`;
  }
};

test("keystore.json valid rows: parse, serialize(parse(x)) === x, the vault texts untouched", () => {
  assert.ok(K.valid.length >= 5);
  for (const r of K.valid) {
    const c = parse(r.text);
    assert.equal(serialize(c), r.text, r.id);
    for (const s of c.seeds)
      for (const [k, v] of Object.entries(s.vaults)) assert.ok(r.text.includes(JSON.stringify(v)), `${r.id} ${k}`);
  }
  assert.deepEqual(parse(K.valid[0].text).seeds, [], "an empty keystore");
});

test("keystore.json refused rows: each by its name; the base with the rule fixed parses", () => {
  const names = new Set();
  for (const r of K.refused) {
    assert.equal(codeOf(r.text), r.error, r.id);
    names.add(r.id);
  }
  for (const want of [
    "another format",
    "v: 1 (vault v1, no migration)",
    "a vault of another seed's id",
    "a vault v 1 text",
    "an unknown top-level field",
    "an unknown seed field",
    "an unknown account field",
    "a duplicate id",
    "a duplicate label",
    "a label of 0 scalar values",
    "a label of 65 scalar values",
    "a label with a control character",
    "a label not NFC",
    "words 13",
    "backup lost",
    "a vaults key unequal to its vault's label",
    "no seed vault",
    "no rev",
    "no indexMac",
    "65 seeds",
    "depth 6",
  ])
    assert.ok(names.has(want), want);
  // the controls: the base (K.valid "four seeds" cut to two, rev 7) and one-field fixes
  const four = parse(K.valid.find((r) => r.id === "four seeds").text);
  const base = { ...four, rev: 7, seeds: four.seeds.slice(0, 2) };
  assert.equal(codeOf(serialize(base)), "ok");
  const fixed = structuredClone(base);
  fixed.seeds[0].label = "ư".repeat(64);
  assert.equal(codeOf(JSON.stringify(fixed)), "ok", "64 scalar values");
  fixed.seeds[0].words = 12;
  assert.equal(codeOf(JSON.stringify(fixed)), "ok", "words 12");
  fixed.seeds[0].backup = "pending";
  assert.equal(codeOf(JSON.stringify(fixed)), "ok", "backup pending");
  assert.equal(depthOf(JSON.stringify(base)), 5);
});

test("keystore.json: each entry's indexMac is its seed's over its fields and vault texts, the seed vaults open with the passphrase", async () => {
  const four = parse(K.valid.find((r) => r.id === "four seeds").text);
  for (const s of four.seeds) {
    const entropy = await openSeedVault(JSON.parse(s.vaults.seed), { pin: K.passphrase });
    assert.equal((entropy.length * 3) / 4, s.words);
    const { indexMac: mac, ...fields } = s;
    assert.equal(indexMac(entropy, fields), mac, s.label);
    // the MAC covers the vault texts (T13b ruling 3): another manifest text is another MAC
    const swapped = {
      ...fields,
      vaults: { ...fields.vaults, manifest: four.seeds.find((x) => x !== s).vaults.manifest },
    };
    assert.notEqual(indexMac(entropy, swapped), mac, `${s.label}: the vaults are covered`);
  }
});

test("property: random mutations of valid rows are accepted or refused by name, never another throw", () => {
  let n = 0,
    refused = 0;
  for (const r of K.valid) {
    const b = utf8ToBytes(r.text);
    for (let i = 0; i < 150; i++, n++) {
      const rnd = shake256(utf8ToBytes(`ks.mut.${r.id}.${i}`), { dkLen: 12 });
      const at = ((rnd[0] << 16) | (rnd[1] << 8) | rnd[2]) % b.length;
      const m = b.slice();
      if (rnd[3] % 3 === 0) m[at] = rnd[4];
      else if (rnd[3] % 3 === 1)
        m[at] = 0x7b; // '{'
      else m.copyWithin(at, Math.min(b.length - 1, at + 1));
      const text = new TextDecoder().decode(m);
      const c = codeOf(text);
      assert.ok(["ok", "VaultFormat", "VaultVersion"].includes(c), `${r.id} #${i}: ${c}`);
      if (c !== "ok") refused++;
    }
  }
  assert.ok(refused > n / 2, `most mutations refused (${refused} of ${n})`);
  assert.equal(codeOf("{".repeat(1 << 16)), "VaultFormat", "deep nesting stops at the scan");
  assert.equal(codeOf("x".repeat((16 << 20) + 1)), "VaultFormat", "over 16 MiB");
});

test("the generator reproduces keystore.json byte for byte", () => {
  const out = mkdtempSync(join(tmpdir(), "keystore-vectors-"));
  try {
    execFileSync(process.execPath, [fileURLToPath(new URL("../scripts/keystore-vectors.mjs", import.meta.url)), out]);
    assert.equal(readFileSync(join(out, "keystore.json"), "utf8"), readFileSync(join(DIR, "keystore.json"), "utf8"));
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
});
