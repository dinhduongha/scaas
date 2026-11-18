// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// scaas-sdk plan T6: roots (c) and (d) (spec §6.6, §25 Q-K4, Q-K5, Q-K18) against smartcontracts/vectors/keys/roots.json, which
// the generator reproduces byte for byte (test/bip85.test.js runs it once for both files).
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { hashTypedData, evmAddress } from "../src/evm.js";
import { entropyToWords, keyDerivationTypedData, rootFromEoaSignature, rootFromKey, signature65 } from "../src/seed.js";
import { hex, fromHex } from "../src/bytes.js";

const v = JSON.parse(
  readFileSync(fileURLToPath(new URL("../../../smartcontracts/vectors/keys/roots.json", import.meta.url)), "utf8"),
);
const E = v.eoaSig;
const R = v.rawKey;

test("root (c) typed data: chain-free domain {name, version, salt}, KeyDerivation(warning, account, set)", () => {
  const td = keyDerivationTypedData(E.account, 0);
  assert.deepEqual(JSON.parse(JSON.stringify(td)), E.typedData);
  assert.equal(hex(hashTypedData(td)), E.digest);
  assert.deepEqual(
    td.types.EIP712Domain.map((f) => f.name),
    ["name", "version", "salt"],
    "no chainId, no verifyingContract",
  );
  assert.equal(evmAddress(secp256k1.getPublicKey(fromHex(E.key), false)), E.account);
});

test("root (c): every row; high-s, v in {0, 1} and the converted compact form give the one root; another set another", () => {
  for (const r of E.rows) {
    let s = fromHex(r.signature);
    if (r.compact) s = signature65(s, { compact: true });
    const root = rootFromEoaSignature({
      account: E.account,
      set: r.set,
      sig1: s,
      sig2: Uint8Array.from(s),
      passphrase: E.passphrase,
    });
    assert.equal(hex(root), r.root, r.id);
    assert.equal(entropyToWords(root).join(" "), r.words);
    assert.equal(r.words.split(" ").length, 24);
  }
  const set0 = new Set(E.rows.filter((r) => r.set === 0).map((r) => r.root));
  assert.equal(set0.size, 1);
  assert.ok(!set0.has(E.rows.find((r) => r.set === 1).root));
});

test("root (c) refusals, each beside its control", () => {
  for (const r of E.refusals) {
    assert.throws(
      () =>
        rootFromEoaSignature({
          account: E.account,
          set: 0,
          sig1: fromHex(r.sig1),
          sig2: fromHex(r.sig2),
          passphrase: r.passphrase,
        }),
      (e) => e.code === r.error,
      r.id,
    );
  }
  assert.equal([...E.passphrase.normalize("NFKC")].length, 10, "control: 10 code points are accepted (the rows)");
});

test("root (d): empty and non-empty passphrase give different roots; index moves it; refusals", () => {
  for (const r of R.rows) {
    const root = rootFromKey({ key: fromHex(R.key), passphrase: r.passphrase, index: r.index });
    assert.equal(hex(root), r.root, r.id);
    assert.equal(entropyToWords(root).join(" "), r.words);
  }
  assert.equal(new Set(R.rows.map((r) => r.root)).size, R.rows.length);
  for (const r of R.refusals) {
    assert.throws(
      () => rootFromKey({ key: fromHex(r.key), passphrase: r.passphrase, index: 0, network: r.network }),
      (e) => e.code === r.error,
      r.id,
    );
  }
});
