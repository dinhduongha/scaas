// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// smartcontracts/vectors/appcore/handles.json reproduced by src/appcore.js, and the refusals around the key-wrap AAD.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import * as ac from "../src/appcore.js";
import { hex, fromHex, concatBytes } from "../src/bytes.js";

const V = JSON.parse(
  readFileSync(new URL("../../../smartcontracts/vectors/appcore/handles.json", import.meta.url), "utf8"),
);
const b = (x) => fromHex(x);

test("derive, mac, macPublic rows", () => {
  for (const r of V.derive) assert.equal(hex(ac.derive(r.keys.map(b), b(r.salt), b(r.info), r.len)), r.okm, r.name);
  for (const r of V.mac) assert.equal(hex(ac.macDerive(b(r.key), b(r.data), r.len)), r.out, r.name);
  for (const r of V.macPublic) assert.equal(hex(ac.macPublic(b(r.key), b(r.data), r.len)), r.out, r.name);
  assert.throws(() => ac.macPublic(b(V.macPublic[0].key), b(V.macPublic[0].data), 9), { code: "Argument" });
});

test("seal and open rows; an aad starting with the key-wrap constant refused", () => {
  for (const r of V.seal) {
    assert.equal(hex(ac.seal(b(r.key), b(r.nonce), b(r.aad), b(r.pt))), r.ct, r.name);
    assert.equal(hex(ac.open(b(r.key), b(r.nonce), b(r.aad), b(r.ct))), r.pt, r.name);
  }
  for (const r of V.sealRandom) {
    assert.equal(hex(ac.sealRandom(b(r.key), b(r.nonce), b(r.aad), b(r.pt))), r.wire);
    assert.equal(hex(ac.openRandom(b(r.key), b(r.aad), b(r.wire))), r.pt);
  }
  const r = V.seal[0];
  const aad = concatBytes(ac.KEYWRAP, b(r.aad));
  assert.throws(() => ac.seal(b(r.key), b(r.nonce), aad, b(r.pt)), { code: "AppKeyUsage" });
  assert.throws(() => ac.open(b(r.key), b(r.nonce), aad, b(r.ct)), { code: "AppKeyUsage" });
});

test("sealKey rows: each opens with its usage only, never by open", () => {
  assert.equal(V.keywrap, hex(ac.KEYWRAP));
  for (const r of V.sealKey) {
    assert.equal(hex(ac.sealKey(b(r.under), b(r.nonce), b(r.key), r.usage, b(r.aad))), r.wire, r.name);
    assert.equal(hex(ac.openKey(b(r.under), b(r.wire), r.usage, b(r.aad))), r.key, r.name);
    for (const other of [1, 2, 3, 4].filter((u) => u !== r.usage))
      assert.throws(() => ac.openKey(b(r.under), b(r.wire), other, b(r.aad)), undefined, `${r.name} as ${other}`);
    // a Data open of the wire fails whatever the aad: the key-wrap prefix is not producible by `seal`
    const w = b(r.wire);
    assert.throws(() => ac.open(b(r.under), w.subarray(0, 12), b(r.aad), w.subarray(12)));
  }
  // and an open_key of a seal output fails
  const s = V.seal[0];
  const wire = concatBytes(b(s.nonce), ac.seal(b(s.key), b(s.nonce), b(s.aad), b(V.sealKey[0].key)));
  assert.throws(() => ac.openKey(b(s.key), wire, 2, b(s.aad)));
});

test("argon2id, kem wrap and unwrap, app root rows", () => {
  for (const r of V.argon2id) assert.equal(hex(ac.argon2id(b(r.password), b(r.salt), r)), r.out, r.name);
  const rc = V.receiver;
  for (const r of V.kemWrap) {
    const w = ac.kemWrap({
      key: b(r.key),
      label: b(r.label),
      aad: b(r.aad),
      kemPk: b(rc.kemPk),
      m: b(r.m),
      x25519Secret: b(r.x25519Secret),
    });
    for (const k of ["kek", "mlkemCt", "x25519Eph", "sealedKey"]) assert.equal(hex(w[k]), r[k], `${r.name} ${k}`);
    const got = ac.kemUnwrap({
      wrap: w,
      label: b(r.label),
      aad: b(r.aad),
      kemPk: b(rc.kemPk),
      dk: b(rc.dk),
      x25519Secret: b(rc.x25519Secret),
    });
    assert.equal(hex(got), r.key, r.name);
    // another label or aad: the KEK differs, the open fails
    const other = new Uint8Array(b(r.label));
    other[other.length - 1] ^= 1;
    assert.throws(() =>
      ac.kemUnwrap({
        wrap: w,
        label: other,
        aad: b(r.aad),
        kemPk: b(rc.kemPk),
        dk: b(rc.dk),
        x25519Secret: b(rc.x25519Secret),
      }),
    );
  }
  for (const r of V.appRoot) assert.equal(hex(ac.appRootKey(b(r.seed), b(r.appId), b(r.ua))), r.key, r.name);
  assert.throws(() => ac.appRootKey(b(V.appRoot[0].seed), new Uint8Array(31), b(V.appRoot[0].ua)), {
    code: "Argument",
  });
});
