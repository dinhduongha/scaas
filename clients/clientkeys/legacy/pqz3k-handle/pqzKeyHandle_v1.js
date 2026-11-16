// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// LEGACY (not loaded): clientkeys `pqzKeyHandle` as it stood at ua-rs-sign 9c12e1aac, with `withSecretOwn` / `withSecretWindow`
// and an acceptance without the token. Superseded by T21 O5 (b) (`withSecretDebit`;
// docs/superpowers/specs/2026-11-16-pqz3k-handle-store.md). Only the handle section of src/pqzopen.js is kept here.
// ------------------------------------------------------------------ the key handle (owner 2026-11-14; Fable P1-1)

const refuse = (why) => { throw new Error(`Refusing: ${why}.`); };
const ZERO20 = new Uint8Array(20);
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const ACCEPTED = new WeakMap(); // acceptance object -> { handle, index, content }: only a handle's check makes one

/** Owner ruling 2026-11-14 (CLI-SGN-51's Change: "no bare class-2 decrypt", enforced in the clients; spec §6, §14.1, §14.18;
 *  Fable P1-1): the wallet's handle of one PQZ key with the opening, `offchain-shared` (`token` omitted) or `offchain-token` of
 *  a token with the opening, at one key version. It derives and holds that key's PQZ seed and its opening KEM secret; no member
 *  returns either. The PQZ seed reaches a function only through three gated entries, each counted: `withSecretOwn(own, f)`
 *  after the holder's own `ownTag` verifies, `withSecretWindow(entries, f)` when every entry is skip-marked, TRIVIAL or accepted
 *  by this handle with the same bytes, and `withSecretKeygen(f)` (the public key and the `R_REG` proof of registration).
 *  `check(credit, verify)` runs K3-7 steps 2-4, 8 and the auditor's opening of step 9 here (the blob read, `aad`s built from the
 *  blob's own bytes, open `O_t`, `O_t` and `O_a` recomputed from `seed_leg`), then hands `seed_leg` to the binding's `verify`
 *  for the PQZ arithmetic of steps 5-7 and `v_a` (pqz-ffi `check_recipient`); `{ accepted, value }` or `{ skip }`, one outcome.
 *  `verify` may be a wallet of `loadPqzWallet` (src/pqzopenWasm.js; TODO 3zf): the handle then hands its opening KEM seed and
 *  the credit read from the blob (`u`, `v` unpacked, `credit.pk` the holder's own PQZ key of this version) to the module's
 *  `check_recipient`, which runs K3-7 steps 3-9 again; `value` = `{ digits, amount }`. The seed goes to no other `verify`.
 *  `credit = { token, index, slot, code, pk?, auditor?: { ua, pk, kemPk }, reads: { block, finalized, strictMajority } }`.
 *  UNAUDITED. */
export function pqzKeyHandle(seed, { account = 0, index = 0, chainUid, token, ua, version, layout }) {
  const kind = token === undefined ? 'offchain-shared' : 'offchain-token';
  const scope = token === undefined ? ZERO20 : asBytes(token, 20, 'token');
  const v = intOf(version, 'version');
  const uaB = asBytes(ua, 32, 'ua');
  const cu = asBytes(chainUid, 32, 'chainUid');
  if (!layout || !layout.pkp || !layout.vp) refuse('the set layout (pqzLayout(n, packBits)) is needed');
  const id = keccak_256(concatBytes(utf8ToBytes('scaas.pqz3k.handle.v1'), cu, scope, uaB, be64(v)));
  let pqzSeed = scopedKeySeed(seed, { account, index, chainUid: cu, token: token === undefined ? undefined : scope, version: v });
  const okSeed = openKemSeed(seed, { ua: uaB, chainUid: cu, token: token === undefined ? undefined : scope, version: v });
  const k = openKemKey(okSeed);
  const kemPk = k.kemPk;
  const kem = { dk: k.dk, x25519Secret: k.x25519Secret };
  let loads = 0;
  let keygens = 0;
  const tokenOk = (t) => kind === 'offchain-shared' || eq(asBytes(t, 20, 'token'), scope);
  const live = () => { if (pqzSeed === null) refuse('this handle was wiped'); return pqzSeed; };

  function check(credit, verify) {
    live(); // review 3w-delta U4h-4: a wiped handle refuses, it never yields a (markable) skip
    const slot = slotOf(credit.slot);
    if (pqzSlotTrivial(slot)) refuse('a TRIVIAL entry is accepted without a check');
    const code = asBytes(credit.code, undefined, 'code');
    const b = pqzOpeningBlobOf(code, layout);
    const tok = asBytes(credit.token, 20, 'token');
    if (!tokenOk(tok) || !eq(b.toUA, uaB) || b.kv[0] !== v) refuse(`the credit is not this ${kind} handle's (token, recipient or key version)`);
    if (b.n === 2 && !credit.auditor) refuse('an audited leg without the auditor\'s keys (a read error, not a skip)');
    const wallet = isPqzWallet(verify);
    const lanes = (p) => pqzUnpack(p, layout.vp / 2);
    if (wallet && lanes(b.pu).length !== verify.pkBytes) refuse('the wallet module is of another parameter set than the layout');
    if (wallet && (!credit.pk || (b.n === 2 && !credit.auditor.pk))) refuse('the PQZ keys of the leg (credit.pk, auditor.pk) are needed');
    const aadT = pqzOpeningAad({ chainUid: cu, token: tok, ua: uaB, keyVersion: v, pu: b.pu, pv: b.pvt });
    const aadA = b.n === 2 ? pqzOpeningAad({ chainUid: cu, token: tok, ua: credit.auditor.ua, keyVersion: b.kv[1], pu: b.pu, pv: b.pva }) : null;
    const content = pqzEntryHash(credit.index, slot, code);
    const skip = () => ({ skip: { index: intOf(credit.index, 'the entry index'), entryHash: hexOf(content), reads: { ...credit.reads } } });
    const seedLeg = openOpening({ opening: b.oT, kemPk, dk: kem.dk, x25519Secret: kem.x25519Secret, aad: aadT });
    if (seedLeg === null) return skip();
    if (!eq(sealOpening({ seedLeg, role: 0, kemPk, aad: aadT }).bytes, b.oT)) return skip(); // step 8
    if (b.n === 2) {
      let oA;
      try { oA = sealOpening({ seedLeg, role: 1, kemPk: credit.auditor.kemPk, aad: aadA }).bytes; } catch { return skip(); }
      if (!eq(oA, b.oA)) return skip(); // step 9, the auditor's opening
    }
    const value = wallet
      ? verify.checkRecipient(okSeed, { chainUid: cu, token: tok, u: lanes(b.pu),
        to: { ua: uaB, keyVersion: v, pk: credit.pk, kemPk, v: lanes(b.pvt), opening: b.oT },
        auditor: b.n === 2 ? { ua: credit.auditor.ua, keyVersion: b.kv[1], pk: credit.auditor.pk, kemPk: credit.auditor.kemPk,
          v: lanes(b.pva), opening: b.oA } : null })
      : verify(seedLeg, { blob: b, aadT, aadA, auditor: credit.auditor ?? null }) ?? null;
    if (value === null) return skip();
    const accepted = Object.freeze({ index: intOf(credit.index, 'the entry index'), entryHash: hexOf(content) });
    ACCEPTED.set(accepted, { handle: id, index: accepted.index, content });
    return { accepted, value };
  }

  return Object.freeze({
    kind, scope: hexOf(scope), version: v, openKem: kemPk,
    check,
    /** How many times the PQZ seed reached `withSecretOwn` / `withSecretWindow`; `withSecretKeygen` apart. */
    get secretLoads() { return loads; },
    get keygens() { return keygens; },
    /** `keccak256(seed32)`: the KAT's view of the derivation, never the seed. */
    seedCommitment: () => hexOf(keccak_256(live())),
    withSecretOwn({ token: t, sendCounter, pu, pvf, ownTag }, f) {
      if (!tokenOk(t)) refuse(`the ciphertext is not this ${kind} handle's token`);
      const s = live();
      const { key, ownTag: want } = pqzOwnTag({ seed32: s, chainUid: cu, token: hexOf(asBytes(t, 20, 'token')), fromUA: uaB, sendCounter, pu, pvf });
      key.fill(0);
      // constant time (T21 L42), as ua-rs: the tag gates the seed for a ciphertext a node supplies
      if (!equalBytes(fromHex(want), asBytes(ownTag, 32, 'ownTag'))) refuse('the ownTag does not verify under this key');
      loads += 1;
      return f(s);
    },
    withSecretWindow(entries, f) {
      for (const e of entries) {
        const slot = slotOf(e.slot);
        if (pqzSlotMarked(slot) || pqzSlotTrivial(slot)) continue;
        const a = e.accepted && ACCEPTED.get(e.accepted);
        if (!a || !eq(a.handle, id) || a.index !== intOf(e.index, 'the entry index') || !e.code || !eq(a.content, pqzEntryHash(e.index, slot, e.code))) {
          refuse('a window entry is neither accepted by this handle, TRIVIAL nor skip-marked');
        }
      }
      const s = live();
      loads += 1;
      return f(s);
    },
    withSecretKeygen(f) {
      const s = live();
      keygens += 1;
      return f(s);
    },
    /** Wipes both secrets; the handle refuses every entry afterwards. */
    wipe() { if (pqzSeed) pqzSeed.fill(0); pqzSeed = null; kem.dk.fill(0); kem.x25519Secret.fill(0); okSeed.fill(0); },
  });
}

