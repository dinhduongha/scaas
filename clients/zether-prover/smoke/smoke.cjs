// Headless Node smoke test of the WASM build: derive keys from a seed, prove a transfer,
// verify it with the Rust verifier compiled to wasm, and cross-check with native vectors.
// Run via ../wasm-smoke.sh (builds pkg/ first).
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const { zetherCall } = require("../pkg/zether_prover.js");

const call = (cmd, req) => JSON.parse(zetherCall(cmd, JSON.stringify(req)));
const mnemonic = Array(23).fill("abandon").concat("art").join(" ");
const token = "0x5fbdb2315678afecb367f032d93f642f64180aa3";
const r33 = JSON.parse(fs.readFileSync(path.join(__dirname, "../vectors/r33_keys.json"), "utf8"));
let n = 0;

for (const curve of ["bls12381"]) {
  const k0 = { mnemonic, coin: 60, account: 0 };
  const k1 = { mnemonic, coin: 60, account: 1 };
  const from = call("keygen", { curve, key: k0, revealSecret: true });
  const to = call("keygen", { curve, key: k1 });
  // Same R33 key as the native vectors.
  assert.equal(from.x, r33[curve].keys[0].x);
  assert.equal(from.UA, r33[curve].keys[0].UA);
  n++;

  const acc = call("encrypt", { curve, Y: from.Y, amount: 50000 });
  assert.equal(call("decrypt", { curve, key: k0, ct: acc, tableBits: 18, boundBits: 24 }).amount, "50000");
  assert.equal(call("checkBalance", { curve, key: k0, acc, balance: "50000" }).ok, true);
  assert.equal(call("checkBalance", { curve, key: k0, acc, balance: "50001" }).ok, false);
  // wasm refuses the 2 GiB table (limits §4): only the native zether-read-balance goes to 2^27.
  assert.throws(() => zetherCall("decrypt", JSON.stringify({ curve, key: k0, ct: acc, tableBits: 27 })), /wasm/);
  // review L4: a browser tab stays at <= 2^24 (256 MiB) unless the caller opts in.
  assert.throws(() => zetherCall("decrypt", JSON.stringify({ curve, key: k0, ct: acc, tableBits: 25 })), /allowLargeTable/);
  n++;

  const t0 = Date.now();
  const tx = call("proveTransfer", {
    curve, key: k0, chainId: 31337, chainUid: "0x" + "24".repeat(32), token, sendCounter: 0, accSeq: 1, validUntilBlock: 100, acc, balance: 50000,
    yTo: to.Y, amount: 1234, fee: 10, beneficiary: "0x" + "22".repeat(32),
  });
  const ms = Date.now() - t0;
  assert.deepEqual(call("verifyTransfer", { curve, statement: tx.statement, proof: tx.proof }), { ok: true });
  n++;
  const flipped = tx.proof.slice(0, -1) + (tx.proof.endsWith("0") ? "1" : "0");
  assert.equal(call("verifyTransfer", { curve, statement: tx.statement, proof: flipped }).ok, false);
  n++;

  // wasm proof → native verifier (release CLI), and native vector → wasm verifier.
  const cli = path.join(__dirname, "../target/release/zether-cli");
  if (fs.existsSync(cli)) {
    const out = execFileSync(cli, ["verifyTransfer"], {
      input: JSON.stringify({ curve, statement: tx.statement, proof: tx.proof }),
    });
    assert.equal(JSON.parse(out).ok, true);
    n++;
  }
  const vec = JSON.parse(fs.readFileSync(path.join(__dirname, `../vectors/transfer_${curve}.json`), "utf8"));
  assert.equal(call("verifyTransfer", { curve, statement: vec.statement, proof: vec.proof }).ok, true);
  n++;

  // Storage-only recovery of a commit-reveal transfer (CTR-ZTH-50): entry = keccak256(R) ‖ memo (the commitment from
  // the calldata path), openMemo → the keys registry.keyOf would return → recoverTransfer rebuilds R.
  const chain = { curve, key: k0, chainId: 31337, chainUid: "0x" + "24".repeat(32), token, sendCounter: 0 };
  const mt = call("proveTransferMulti", {
    ...chain, accSeq: 1, validUntilBlock: 100, acc, balance: 50000, disclosureMode: "compact", recipients: [{ yTo: to.Y, amount: 1234 }],
  });
  assert.equal(mt.mode, "compact");
  const entry = call("recoverTransfer", { ...chain, payload: mt.payload }).commitment + mt.memo.slice(2);
  const memo = call("openMemo", { ...chain, entry });
  assert.deepEqual([memo.needKeys, memo.legs[0].amount, memo.salt], [[to.UA], "1234", mt.salt]);
  assert.equal(call("recoverTransfer", { ...chain, entry, keys: [to.Y] }).bundles, mt.bundles);
  assert.throws(() => zetherCall("recoverTransfer", JSON.stringify({ ...chain, entry })), /keyOf/);
  n++;

  // the UA registry's PoP (CTR-UA-07) equals the native vector's: same key, chain, chainUid, registry, no PQZ key
  const v = r33[curve].keys[0].pop;
  const pop = call("pop", { curve, key: k0, chainId: v.chainId, chainUid: v.chainUid, registry: v.registry });
  assert.deepEqual([pop.UA, pop.kind, pop.popDigest, pop.uaMsg], [from.UA, v.kind, v.popDigest, v.uaMsg]);
  n++;

  assert.throws(() => zetherCall("proveTransfer", JSON.stringify({ curve, key: k0 })));
  n++;
  console.log(`${curve}: proveTransfer ${ms} ms in wasm`);
}
console.log(`wasm smoke: ${n} checks passed`);
