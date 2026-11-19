// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// scaas-sdk T13b: the sponsored registration blobs (smartcontracts/vectors/ua/registration_blobs.json) are what
// src/ua.js registrationBlob gives today, and each commit-form blob's `kem` hashes to its `kemPkHash`.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { blobRows } from "../scripts/registration-blob-vectors.mjs";
import { keccak_256, hex, fromHex } from "../src/bytes.js";

const file = JSON.parse(
  readFileSync(fileURLToPath(new URL("../../../smartcontracts/vectors/ua/registration_blobs.json", import.meta.url))),
);

test("registration blobs regenerate byte for byte", () => {
  assert.deepEqual(file.blobs, blobRows());
});

test("a commit-form blob carries the KEM key its kemPkHash commits to", () => {
  const commits = file.blobs.filter((b) => b.blob.kem);
  assert.ok(commits.length > 0);
  for (const { name, blob } of commits) {
    assert.equal(hex(keccak_256(fromHex(blob.kem.kemPk))), blob.args.attrs.kemPkHash, name);
    assert.equal(blob.args.attrs.kem.mlkemEk, "0x", name);
  }
  for (const { name, blob } of file.blobs.filter((b) => !b.blob.kem))
    assert.equal(blob.args.attrs.kemPkHash, `0x${"00".repeat(32)}`, name);
});
