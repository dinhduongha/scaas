// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// scaas-sdk plan T20g: the JS / TS binding (spec §16.4) in Node, through wasm-bindgen's output (pkg/, built by ../run.sh).
// Rows: smartcontracts/vectors/keystore/keystore.json, each container the JS store's `keystore`: valid rows list their seeds
// and every seed opens with the rows' passphrase (its accounts listed); refused rows fail with their named error. Then: a JS
// authenticator's PRF through the copy call (passkey unlock), `next` on the subscription, a JS exception in the store and in
// the authenticator (the SDK's error), the copy call zeroing the caller's array, a released handle refused, the load check.
// A panic is not caught on wasm32 (spec §16.1: no `catch_unwind` there), so none is provoked.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const sdk = require("../pkg/scaas_sdk_js.js");
const rows = JSON.parse(
  readFileSync(new URL("../../../../../smartcontracts/vectors/keystore/keystore.json", import.meta.url), "utf8"),
);

const REPO =
  "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";
const PASS = "river-otter-7 ünï";

/** A secret holding `text`, by the copy call (the caller's array zeroed by it). */
function secret(text) {
  const bytes = new TextEncoder().encode(text);
  const h = sdk.secret_new(bytes.length);
  sdk.secret_write(h, bytes);
  return h;
}

/** The SDK's store contract over a Map: `put_if` refuses another revision with `Conflict`. */
class MemStore {
  items = new Map();
  throws = false;
  get(name) {
    if (this.throws) throw new Error("the app's store threw");
    const b = this.items.get(name);
    return b === undefined ? null : { bytes: b, rev: sdk.rev_of(b) };
  }
  put_if(name, prevRev, bytes) {
    const have = this.items.has(name) ? sdk.rev_of(this.items.get(name)) : undefined;
    if (have !== prevRev) throw new Error("Conflict");
    this.items.set(name, new Uint8Array(bytes));
  }
  delete(name) {
    this.items.delete(name);
  }
  // one caller at a time here: no lock to hold
  lock() {
    return 1;
  }
  unlock() {}
}

/** A PRF: 32 bytes from the salt (deterministic, a test stand-in), written by the copy call into the secret `prfOut` names. */
class FakeAuth {
  throws = false;
  async get_assertion(req, prfOut) {
    if (this.throws) throw new Error("the app's authenticator threw");
    const salt = req.prf_salt;
    if (!salt) throw new Error("Refused");
    const out = new Uint8Array(32).map((_, i) => salt[i % salt.length] ^ 0x5a ^ i);
    sdk.secret_write(prfOut, out);
    return {
      credential_id: [0xc1, 0xed],
      authenticator_data: new Array(37).fill(0),
      client_data_json: [],
      signature: new Array(64).fill(0),
      prf: true,
    };
  }
  create_passkey() {
    throw new Error("Unavailable");
  }
  platform_secret() {
    throw new Error("Unavailable");
  }
  p256_generate() {
    throw new Error("Unavailable");
  }
  p256_sign() {
    throw new Error("Unavailable");
  }
}

const config = (expect_api = 1, need_features = sdk.features()) => ({
  expect_api,
  need_features,
  profiles: [],
  rp_id: "wallet.example",
  limits: sdk.limits_default(),
  gas_tables: [],
});

function over(text) {
  const st = new MemStore();
  st.items.set("keystore", new TextEncoder().encode(text));
  return sdk.open(config(), st, new FakeAuth());
}

/** The error's code (its message), or "Ok". */
async function failure(p) {
  try {
    await p;
    return "Ok";
  } catch (e) {
    return e.message;
  }
}

test("load check", async () => {
  assert.equal(sdk.api_version(), 1);
  // the opening refuses a library of another api_version or without a needed feature (spec §16.3)
  assert.equal(await failure(sdk.open(config(2), new MemStore())), "AbiMismatch");
  assert.equal(await failure(sdk.open(config(1, 1n << 62n), new MemStore())), "AbiMismatch");
  assert.equal(await failure(sdk.open(config(), new MemStore())), "Ok");
});

test("copy calls: a backup revealed and read, nothing left in wasm memory", async () => {
  const s = await sdk.open(config(), new MemStore(), new FakeAuth());
  const fresh = await s.vault().generate({ label: "Fresh", vault_passphrase: secret(PASS) });
  const words = sdk.seed_backup_reveal(fresh.backup);
  const text = new Uint8Array(sdk.secret_len(words));
  sdk.secret_read(words, text);
  assert.equal(new TextDecoder().decode(text).split(" ").length, 24, "the revealed words, read by the copy call");
  text.fill(0);
  assert.ok(sdk.release(words) && sdk.release(fresh.backup));
  // a marker written in and read out leaves no copy in the SDK's memory once released (review B3)
  // 4 KiB, and the scan below looks for its last 64 bytes: a later small allocation that reuses the head of a freed copy
  // cannot hide the rest of it (the B3 mutant survived a 52-byte marker once the allocator reused its chunk)
  const marker = new TextEncoder().encode("marker-9f3c-" + "q".repeat(4020) + "-tail-5e1d7a" + "z".repeat(52));
  const h = sdk.secret_new(marker.length);
  sdk.secret_write(h, marker.slice());
  const out = new Uint8Array(marker.length);
  sdk.secret_read(h, out);
  assert.deepEqual(out, marker);
  assert.ok(sdk.release(h));
  const mem = new Uint8Array(sdk.wasm_memory().buffer);
  assert.equal(
    Buffer.from(mem).indexOf(Buffer.from(marker.subarray(marker.length - 64))),
    -1,
    "no plaintext left in wasm memory",
  );
  // an opaque call without the marker: OpaqueCallRefused, as on every binding (review B2)
  const call = { Opaque: { target: "0x" + "11".repeat(20), value: "0", data: "0x", allow: false } };
  const env = { valid_until: 0n, mode: 0, relayer: null, fee: "0", fee_recipient: null };
  const key = { Ua: { seed: fresh.info.id, kind: 0, account: 0, index: 0 } };
  const req = { signer: key, chain: "x", wallet: "0x" + "22".repeat(20), call, batch: "0", envelope: env };
  assert.equal(await failure(s.wallet().prepare_execute(req)), "OpaqueCallRefused");
});

test("keystore rows", async () => {
  let opened = 0;
  for (const r of rows.valid) {
    const want = JSON.parse(r.text).seeds;
    const s = await over(r.text);
    const got = await s.vault().seeds();
    assert.equal(got.length, want.length, r.id);
    got.forEach((g, i) => {
      const w = want[i];
      assert.deepEqual([g.id, g.label, g.words, g.backup, g.unlocked], [w.id, w.label, w.words, w.backup, false], r.id);
    });
    for (const w of want) {
      await s.vault().unlock(w.id, { Passphrase: secret(rows.passphrase) });
      assert.ok((await s.vault().seed(w.id)).unlocked, `${r.id} ${w.id} unlocked`);
      const ids = (await s.account().accounts(w.id)).map((a) => a.id);
      assert.deepEqual(
        ids,
        w.accounts.map((a) => a.id),
        `${r.id} ${w.id} accounts`,
      );
      opened++;
    }
    if (want.length) {
      await s.vault().lock(want[0].id);
      const e = await failure(s.vault().unlock(want[0].id, { Passphrase: secret("not the one 9") }));
      assert.equal(e, "VaultOpen", `${r.id}: a wrong passphrase`);
    }
  }
  for (const r of rows.refused) {
    const e = await failure(over(r.text).then((s) => s.vault().seeds()));
    assert.equal(e, r.error, r.id);
  }
  // control: the rows were read and the seeds opened
  assert.ok(
    rows.valid.length >= 5 && opened >= 5 && rows.refused.length >= 19,
    `${rows.valid.length} valid, ${opened} opened`,
  );
});

test("store, authenticator, PRF, events, copy calls", async () => {
  const st = new MemStore();
  const auth = new FakeAuth();
  const s = await sdk.open(config(), st, auth);
  const sub = s.subscribe();
  assert.equal(await sub.next(50), undefined, "next: nothing yet");

  // the copy call zeroes the caller's array; a secret is never a string
  const words = new TextEncoder().encode(REPO);
  const wh = sdk.secret_new(words.length);
  sdk.secret_write(wh, words);
  assert.ok(
    words.every((b) => b === 0),
    "the caller's array zeroed",
  );
  const id = (await s.vault().import_words({ label: "Main", words: wh, vault_passphrase: secret(PASS) })).id;
  let changed = false;
  for (let ev; (ev = await sub.next(200)) !== undefined; ) changed ||= "KeystoreChanged" in ev;
  assert.ok(changed, "next: KeystoreChanged");

  // the PRF return: a JS authenticator writes it by the copy call; the passkey unlock opens the seed with it
  await s.vault().enable_passkey_unlock(id, secret(PASS));
  await s.vault().lock(id);
  await s.vault().unlock(id, "Passkey");
  assert.ok((await s.vault().seed(id)).unlocked, "passkey unlock by the PRF");

  // a JS exception in the authenticator: Unexpected on the Rust side, the SDK's refusal here
  await s.vault().lock(id);
  auth.throws = true;
  const ea = await failure(s.vault().unlock(id, "Passkey"));
  assert.equal(ea, "AuthenticatorRefused", "authenticator exception");
  auth.throws = false;
  // a JS exception in the store: Unexpected, the store's failure (VaultIo)
  st.throws = true;
  assert.equal(await failure(s.vault().seeds()), "VaultIo");
  st.throws = false;
  assert.equal((await s.vault().seeds()).length, 1, "control: the store again");

  // a released secret is refused by name
  const h = secret(PASS);
  assert.ok(sdk.release(h));
  assert.equal(await failure(s.vault().unlock(id, { Passphrase: h })), "Argument");
  // review T26 C-12: a refusal whose text names OpaqueCallRefused is still Argument; only the marker's own is that code
  assert.equal(await failure(s.vault().unlock(id, { OpaqueCallRefused: h })), "Argument");
});

test("an EVM profile opens: the bindings build the SDK's `evm` (decisions CLI-SDK-33 (100))", async () => {
  assert.notEqual(sdk.features() & (1n << 30n), 0n, "the evm bit");
  const profile = (more) => ({
    key: "local",
    family: "Evm",
    chain_id: 31337n,
    chain_uid: "0x" + "60".repeat(32),
    rpc: [{ url: "http://127.0.0.1:9", class: "Named", label: null, auth: null }],
    rpc_policy: "Failover",
    gateways: [],
    registry: null,
    factory: null,
    router: null,
    finality: "Finalized",
    tx_gas_cap: null,
    tokens: [],
    gas: sdk.gas_rows_default(),
    gas_opt_in: [],
    max_valid_secs: null,
    verifiers: [],
    verifier_policy: "Failover",
    dexes: [],
    wrappers: [],
    family_params: null,
    l1_fee: null,
    disabled_kinds: [],
    ...more,
  });
  const open = (p) => sdk.open({ ...config(), profiles: [p] }, new MemStore());
  assert.equal(await failure(open(profile({}))), "Ok");
  // the merge's fields reach the SDK: the OP Stack L1 fee and a disabled kind open; an unknown kind is refused by name
  assert.equal(await failure(open(profile({ l1_fee: "OpStack", disabled_kinds: ["pqz"] }))), "Ok");
  assert.equal(await failure(open(profile({ disabled_kinds: ["no-such-kind"] }))), "Argument");
  // Moonbeam's pinnedReads false (owner 2026-11-22, ARCH-POS-20 (2)): the profile opens; absent, the field is true
  assert.equal(await failure(open(profile({ pinned_reads: false }))), "Ok");
});

test("a value nested beyond 128 levels is refused before it is lifted, and the instance lives on (review T26 C-6)", async () => {
  const s = await sdk.open(config(), new MemStore());
  let deep = 0;
  for (let i = 0; i < 100000; i++) deep = [deep];
  const blob = (extra) => ({
    v: 1,
    chain_uid: "0x" + "60".repeat(32),
    family: "evm",
    contract: "0x" + "11".repeat(20),
    entry: "mtxCancelNonce",
    struct: "UACancelNonce",
    kind: "token",
    message: {},
    extra,
    signature: "0x",
    signer: "0x" + "22".repeat(32),
    signer_kind: 0,
    ids: false,
  });
  const expect = { chain: "nowhere", payee: [], payer: { Native: { seed: "none", network: "evm", index: 0 } } };
  assert.equal(await failure(s.op().import_signed(blob(deep), expect)), "Argument");
  let ok = 0;
  for (let i = 0; i < 100; i++) ok = [ok];
  assert.equal(await failure(s.op().import_signed(blob(ok), expect)), "ChainUnknown", "the twin: 100 levels lift");
  assert.deepEqual(await s.vault().seeds(), [], "the instance lives on");
});
