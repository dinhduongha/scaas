# UA-2a — UARegistry generation 1 core and the classical verifiers (P-256, WebAuthn, BIP-340, Schnorr, BLS min-sig) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** the first of three UA-2 sub-plans ([roadmap](2026-10-12-ua-roadmap.md); owner 2026-10-12: UA-2a registry core and
the simple classical verifiers, UA-2b ed25519 in Solidity, UA-2c MuSig2 / FROST and `groups.json`): `UARegistry`
generation 1 (records, `keyOwner`, PoP registration, `requireAuthorized` for derived, native ECDSA / EIP-7702 / ERC-1271 with
`UAAuth`, and `msig` structures with the gas bound; capped verifier calls that fail closed; generations; `chainUid`;
`hederaNative`; ERC-5267), the verifiers for `webauthn-p256`, `p256`, `bip340`, `schnorr-bn254`, `schnorr-bls12381`,
`bls12381-minsig`, `bls-bn254-minsig`, and the signature vectors `smartcontracts/vectors/ua/signatures.json` with a node
re-verification and an independent Rust cross-check. Not here: ed25519 (UA-2b), MuSig2 / FROST / `keyPtr` storage (UA-2c),
PQ kinds (P6c), Zether kinds, `requireZetherAuthorized` and deployment (UA-3), the UA ledger (UA-4).

**Architecture:** Each verifiable kind has a stateless verifier contract (`IUAKindVerifier.verify` for authorization,
`IUAPopVerifier.verifyPop` for registration; they differ only for the BLS kinds, whose PoP uses its own DST / label).
`UARegistry` holds one immutable per kind slot (`verifier | cap << 160`) set by its constructor and calls the verifier with
a capped `staticcall`, counting only an exact 32-byte `1`. Native ids and `msig` structures are checked inside the
registry. Every tag, id, message and digest comes from UA-1's `UAKinds`; the vectors come from one generator (clientkeys)
and are re-verified by noble (node) and by an independent Rust implementation (`scaas-ua::verify`) before forge reads them.

**Tech Stack:** Solidity ^0.8.20, Foundry (forge 1.3.5, `evm_version = "osaka"`; a `prague` run checks chains without
P256VERIFY), OpenZeppelin 5.2 (`P256`, `ECDSA`, `Base64`, `IERC1271`, `IERC5267`, `Clones`); EIP-2537 (BLS12-381), bn254
`0x06`–`0x08`, P256VERIFY `0x100` (EIP-7951) probed in the constructor, `MODEXP`; Node 22 with the clientkeys `@noble/*`
already in `package.json` (no new npm dependency); Rust 1.90 with `scaas-ua` + `k256` (`ecdsa`, `schnorr`), `p256`
(`ecdsa`), `sha2 = "=0.10.9"`, arkworks (already locked).

**Spec:** `docs/contracts/accounts.md` §1.4 (registration, PoP), §1.5 (purposes, `UAAuth`), §1.6 (kind table, closed sets),
§1.8 (`IUARegistry`, register steps, storage, generations), §1.9 (verifiers), §1.10 (EIP-7702, chain identity), §1.15 (gas),
§1.16 (vectors; T-REG, T-AUTH, T-CHAIN, T-MEMBER, T-GAS); the roadmap's UA-2 row (carry-overs from UA-1).

**Base:** `main` at the commit that adds this plan (parent `ee86883`). Every task was built as a spike in a scratch copy on
2026-10-12 and run green: vectors node 6/6 and Rust 2 + 5 (+ UA-1's 6) with clippy clean; ECC verifiers 16/16 on osaka and
15 + 1 skipped on prague, SmartKeyAccount 51/51; pairing verifiers 13/13 and the old registry 22/22; registry 28 + 3 + 5
(+ UAKinds 9) with the size gate at 0 errors. Not run in scratch: the full repo suite on the merged tree, CI.

## Global Constraints

- Paths relative to `/home/ha/work/ainative/scaas`; worktree `.claude/worktrees/ua2a` on branch `ua2a-registry` from `main`.
  Heavy commands (forge, cargo, node tests) only through `scripts/capped`, one at a time. `/usr/bin/git` and `/usr/bin/grep`
  in worktrees. forge commands run in `smartcontracts/evm`.
- Task order is fixed: 1 vectors → 2 ECC verifiers (creates `src/ua/IUAVerifier.sol`) → 3 pairing verifiers → 4 registry
  core → 5 registry on the vectors + T-GAS → 6 docs. Tasks 2, 3 and 5 read `smartcontracts/vectors/ua/signatures.json`.
- `signatures.json` is generated (never hand-edited) by `clients/clientkeys/scripts/ua-sig-vectors.mjs`; the node test
  checks the generator reproduces it byte for byte. `kinds.json` and `structures.json` (UA-1) are not modified.
- Every verifier returns `false` and never reverts on malformed input (lengths, encodings, off-curve / out-of-subgroup
  points, out-of-range scalars), except `UAKinds.UAVerifyGas()` when it was given less gas than its bounded check needs.
- The registry counts a verifier / ERC-1271 answer only if it is exactly 32 bytes equal to `1` / the 1271 magic; a
  revert, short data or running out of the cap is a failure, never an authorization. A caller that leaves less gas than
  the cap needs gets `UAVerifyGas`.
- `register` derives nothing from `msg.sender`; the registry is admin-free, has no `payable`, and its records are
  monotonic. All chains are test chains: later sub-plans extend the registry by redeploying it (no migration).
- No size optimisation (owner: wait for Glamsterdam); the size gate (`scripts/size_gate.py`, ratchet baseline) must pass.
- Commit trailer: the model that wrote the commit, e.g. `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Never
  `git add` `claude-code-api.txt`, `out/`, `cache/`, `target/`, `node_modules/`.

## Review Focus

- **Fail-closed verifier calls:** a verifier that reverts, returns 31/33 bytes, returns `2`, or burns its cap never
  authorizes; a precompile that consumes all gas on an invalid point must not take the caller's transaction with it (the
  pairing verifiers' bounded self-call); starving the cap yields `UAVerifyGas`, not `false` accepted as "checked".
- **Replay across contexts:** a PoP made for context B, C (same chain id, other `chainUid`) or D (other registry), a
  `UAAuth` signature of another generation or purpose, a signature under a sibling kind's tag, the BLS signature DST used
  as PoP DST and vice versa — all refused (signatures.json negatives, run in Tasks 2, 3 and 5).
- **Native edge cases:** `ecrecover` → `address(0)` never satisfies ua 0 or an `evm-eoa` member with id 0; high-s refused;
  a raw-digest signature (not `UAAuth`) refused; code classification at call time (empty / exact 23-byte EIP-7702
  designator / other code → 1271 only) and the 50 k / 400 k (SmartKeyAccount clone codehash) 1271 caps.
- **msig ordering:** strictly increasing member index, duplicates refused, a MemberSig after the threshold is reached
  refused, a native member with non-empty `keyData` refused, a derived member whose key does not hash to its id refused,
  and the registration bound (Σ of the `c` largest member caps + `MSIG_MEMBER_GAS` per member ≤ `verifyBudget`).
- **Malformed blobs:** WebAuthn ABI blobs with bad offsets or lengths, clientDataJSON outside the strict grammar
  (`crossOrigin:true`, extra member before `crossOrigin`, `webauthn.create`), missing UP / UV, an `msig` auth that does not
  ABI-decode — none authorize (an undecodable `auth` may revert without data; see R21).

## Rulings (docs vs code) and defaults taken

- **R1** Signatures go into a new `signatures.json`; the UA-1 identity files stay untouched (the roadmap said "PoP
  signatures in `kinds.json`").
- **R2** The `bls-bn254-minsig` PoP label is `SCAAS-UA-BLS-BN254-POP-V1` (the spec says only "POP label").
- **R3** `IUAKindVerifier` moves verbatim from `PqUA.sol` to `src/ua/IUAVerifier.sol`, beside `IUAPopVerifier is
  IUAKindVerifier { verifyPop }`; the PQ verifiers import it from there.
- **R4** The P-256 verifiers probe P256VERIFY once in the constructor (a fixed valid vector must give exactly `1` and the
  same vector with `h ^ 1` must not) into an immutable `PRECOMPILE`; with it an invalid signature costs ~11 k instead of the
  ~260 k OpenZeppelin `P256.verify` spends (it reads the precompile's empty "invalid" answer as "no precompile").
- **R5** The pairing verifiers run their check in a self-call bounded by `CHECK_GAS` (an EIP-2537 / bn254 precompile given
  an invalid point consumes all gas passed to it); below `CHECK_GAS·64/63 + 5000` they revert `UAVerifyGas`. Gen-1 default
  caps: `webauthn-p256` 400 k, `p256` 400 k, `bip340` 50 k, `schnorr-bn254` 50 k, `schnorr-bls12381` 70 k, `bls12381-minsig`
  200 k, `bls-bn254-minsig` 345 k.
- **R6** `bls-bn254-minsig`'s try-and-increment map is unbounded: with `CHECK_GAS` 330 k a digest whose map needs more than
  39 extra iterations (p ≈ 2^-39) cannot be authorized — accepted (private-chain kind; the caller's next nonce gives a new
  digest).
- **R7** Verifier contract names as built (`P256Verifier`, …), not the `UA…` prefix of the PQ verifiers — cosmetic.
- **R8** `CurveSigs` is extracted from the old `UniversalAccountRegistry` (`_schnorr`, `_blsBn254`, the BLS12-381 check, with
  tag / label / DST as parameters); there a malformed bn254 Schnorr `R`/`Y` now gives `InvalidProofOfPossession` instead of
  `G1Bn254.BadPoint` (test chains; UA-3 retires that registry to `legacy/`).
- **R9** The clientDataJSON grammar moves to `WebAuthnClientData.parse` (origin returned, not judged), shared with
  `SmartKeyAccount._clientDataOk` (accept set unchanged; +59 bytes runtime).
- **R10** §1.15's estimates are replaced by the measured numbers (Task 6).
- **R11** `msig` auth follows §1.9: `auth = abi.encode(bytes keyData, bytes sig)` with `sig = abi.encode(MemberSig[])`.
- **R12** A native member's `MemberSig.keyData` must be empty, else `UAUnauthorized` (the spec is silent).
- **R13** `signatures.json` carries the 15 official BIP-340 vectors with 32-byte messages; the scaas Schnorr and the bn254
  `mapToG1` vectors are self-consistency only (both implementations are ours) — the file's `note` says so.
- **R14** `scaas-ua` gains a `verify` module (k256 + `ecdsa`/`schnorr`, p256 + `ecdsa`, `sha2 = "=0.10.9"`; no locked
  version moves).
- **R15** The kind table is one immutable per slot (`verifier | cap << 160`) from a `KindConfig[]` constructor argument (no
  SLOAD / EXTCODECOPY at verify time); slots `0x0100`–`0x0107` + `msig` (the `ed25519` slot exists, so UA-2b only configures
  it); MuSig2 / FROST, PQ and Zether kinds are refused by the constructor with `UAConfig(kind)` until their sub-plans.
- **R16** `MSIG_MEMBER_GAS = 35_000` (measured worst per-member overhead, cold under `--isolate`: 19,987 for a member
  handed to gen 1, + the 63/64 hold of the largest cap, 11,349 = 31,336; a member handed to gen 1 adds gen 1's own hold
  `cap / 63 + 5 k` in `_checkMembers`), proven end to end by `UAGas.t.sol` `test_T_GAS_msigAtBudget`.
- **R17** In the msig bound a native member counts at the 400 k 1271 cap whenever the chain has a SmartKeyAccount
  implementation (a counterfactual clone may appear later at the member's address).
- **R18** Generation 2 reads generation 1 for every lookup and hands gen-1 records, and members of kinds it does not enable,
  to the predecessor's `requireAuthorized`; its constructor refuses a keyHash group that gen 1 enables.
- **R19** HIP-632 `isAuthorizedRaw` cannot run in a static frame, so `requireAuthorized` (a `view`) verifies `0x0003` ids and
  members as `0x0001`/`0x0002` (ECDSA / 1271); the HIP-632 path is an open question for the Hedera profile (Task 6 notes
  it in §1.6).
- **R20** Member kinds outside the layout (Zether, structures, foreign native, unknown) fail UA-1's layout check with
  `UAKeyData` (pinned by `kinds.json`); only `hedera-native` outside a Hedera profile gives `UAMemberUnknown` (Task 6 updates
  the §1.8 comment).
- **R21** An `auth` that does not ABI-decode reverts without data (fail closed) instead of `UAUnauthorized`.
- **R22** Additions to the §1.8 surface: constructor error `UAConfig(uint16)`, public `chainKeyHash()`, `IUARegistry is
  IERC5267`; an `msig` registration with a non-empty `pop` reverts `UAPoP`; `requireZetherAuthorized` and `authRef` come with
  UA-3 (`recordOf` returns `authRef = 0`).
- **R23** The `bls-bn254-minsig` cap stays 345 k (4.7 k measured slack; a gas-schedule change means redeploying with a higher
  cap); its `register` needs ≥ 450,243 call gas because of the 63/64 holds — relayers must not estimate below that.
- **R24** `UAKinds.tag()` rebuilding the tag string is not optimised (no gas / size work in this phase).

## Open questions (not blocking)

- HIP-632 for `hedera-native` in a `view` (R19): a non-view entry point or a Hedera-specific path.
- Should `UAKinds` / `kinds.json` move member kinds outside MEMBER from `UAKeyData` to `UAMemberUnknown` (R20)?
- BIP-340 keys with `Px ≥ n` (p ≈ 2^-128) register but cannot be verified by the `ecrecover` trick — documented in the
  verifier.
- A chain that gains P256VERIFY after deployment stays on the Solidity path until the P-256 verifiers are redeployed.

## Out of scope (next sub-plans)

UA-2b (`ed25519` verifier, T-FUZZ), UA-2c (MuSig2 KeyAgg with hints, FROST secp256k1 / bn254 with the DKG check,
`groups.json`, T-FROST, the `keyPtr` storage), P6c (PQ kinds), UA-3 (Zether kinds, `requireZetherAuthorized`, deployment and
the precompile probes per chain), UA-4 (the UA ledger).

---

### Task 1: Signature vectors: generator, node check, Rust cross-check

**Files:**
- Create: `clients/clientkeys/scripts/ua-sig-vectors.mjs`
- Create: `clients/clientkeys/test/ua-sig.test.js`
- Create: `smartcontracts/vectors/ua/signatures.json` (generated, Step 3)
- Create: `clients/scaas-ua/src/verify.rs`
- Create: `clients/scaas-ua/tests/signatures.rs`
- Modify: `clients/scaas-ua/src/lib.rs`, `clients/scaas-ua/Cargo.toml`, `clients/scaas-ua/Cargo.lock` (cargo-resolved)

**Interfaces:**
- Consumes: clientkeys `src/ua.js` (`deriveUA`, `uaMessage`, `popDigest`, `uaAuthDigest`, `memberDigest`, `encodeMsig`,
  `nativeId`, `purposeTag`, `POP_TAG`), `src/bytes.js` (`abiEncode`, `b64url`, `word`); `smartcontracts/vectors/ua/structures.json`
  `contexts` (A, B, C, D); scaas-ua `ua_of`, `ua_message`, `pop_digest`, `ua_auth_digest`, `member_digest`, `encode_msig`.
- Produces: `smartcontracts/vectors/ua/signatures.json` (version 1: `derived` ×7 kinds, `native`, `msig`, `bip340Official`)
  read by the UA-2a verifier and registry forge tests; Rust `scaas_ua::verify::{verify, native_ecdsa, map_to_g1_bn254,
  hash_to_g1_bls12381}` + the DST / label / tag constants.

- [ ] **Step 1: Generator.** Create `clients/clientkeys/scripts/ua-sig-vectors.mjs`:

```js
// Generates smartcontracts/vectors/ua/signatures.json: UA-2a signatures (accounts.md §1.4, §1.8, §1.9) on deterministic
// keys — per derived kind a key, its PoP in structures.json context A and B, signatures over ua_msg under metatx and member,
// and negatives a verifier must refuse; native EOA UAAuth signatures; an msig structure with member signature sets.
// Secrets: keccak256("scaas.ua.vectors.sig.<name>") mod (n − 1) + 1. Nonces: RFC 6979 (P-256, secp256k1 ECDSA), zero
// aux_rand (BIP-340), keccak256(secret ‖ message ‖ "scaas.ua.vectors.nonce") (scaas Schnorr). test/ua-sig.test.js
// re-verifies every row with noble; clients/scaas-ua (tests/signatures.rs) with p256 / k256 / arkworks.
//   node scripts/ua-sig-vectors.mjs [outDir]
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { p256 } from '@noble/curves/nist.js';
import { secp256k1, schnorr } from '@noble/curves/secp256k1.js';
import { bn254 } from '@noble/curves/bn254.js';
import { bls12_381 } from '@noble/curves/bls12-381.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hex, fromHex, keccak_256, utf8ToBytes, concatBytes, b64url, abiEncode, word } from '../src/bytes.js';
import * as ua from '../src/ua.js';

const VECTORS = fileURLToPath(new URL('../../../smartcontracts/vectors/ua/', import.meta.url));
const OUT = process.argv[2] ?? VECTORS;
const { contexts } = JSON.parse(readFileSync(join(VECTORS, 'structures.json'), 'utf8'));

const int = (b) => BigInt(hex(b));
const be = (v, len) => fromHex(v.toString(16).padStart(2 * len, '0'));
const secretOf = (name, n) => (int(keccak_256(utf8ToBytes(`scaas.ua.vectors.sig.${name}`))) % (n - 1n)) + 1n;
const flip = (b, i) => { const c = Uint8Array.from(b); c[i] ^= 1; return c; };
const tag = (p) => ua.purposeTag(p);
const DIGEST = keccak_256(utf8ToBytes('scaas.ua.vectors.sig.digest'));
const ZERO32 = new Uint8Array(32);

// --- schemes: keyData(sk) and sign(sk, msg32, { pop }) ---
const P256_N = p256.Point.Fn.ORDER;
const SECP_N = secp256k1.Point.Fn.ORDER;
const BN = bn254.fields;
const BLS = bls12_381.fields;

const p256Sign = (sk, h) => p256.sign(h, be(sk, 32), { prehash: false, lowS: true, format: 'compact' });
const highS = (sig) => concatBytes(sig.subarray(0, 32), be(P256_N - int(sig.subarray(32, 64)), 32));

const RP_ID = 'scaas.example';
const ORIGIN = 'https://scaas.example';
const CHROME_EXTRA = ',"other_keys_can_be_added_here":"do not compare clientDataJSON against a template. See https://goo.gl/yabPex"';
/** WebAuthn assertion as `abi.encode(bytes authenticatorData, string clientDataJSON, uint256 r, uint256 s)`. */
function webauthnSign(sk, msg, { flags = 0x05, rpId = RP_ID, type = 'webauthn.get', tail = '', counter = 1 } = {}) {
  const authData = concatBytes(sha256(utf8ToBytes(rpId)), Uint8Array.of(flags), be(BigInt(counter), 4));
  const cd = utf8ToBytes(`{"type":"${type}","challenge":"${b64url(msg)}","origin":"${ORIGIN}"${tail}}`);
  const sig = p256Sign(sk, sha256(concatBytes(authData, sha256(cd))));
  return abiEncode(['bytes', 'bytes', 'bytes32', 'bytes32'], [authData, cd, sig.subarray(0, 32), sig.subarray(32, 64)]);
}
const webauthnHighS = (blob) => { const c = Uint8Array.from(blob); c.set(be(P256_N - int(c.subarray(96, 128)), 32), 96); return c; };

const hashToScalar = (seed, r) => ((int(keccak_256(concatBytes(seed, Uint8Array.of(2)))) << 256n)
  + int(keccak_256(concatBytes(seed, Uint8Array.of(3))))) % r;
const SCHNORR_TAG = utf8ToBytes('scaas.ua.schnorr.v1');
const bnG1enc = (P) => { const { x, y } = P.toAffine(); return concatBytes(be(x, 32), be(y, 32)); };
const blsG1enc = (P) => { const { x, y } = P.toAffine(); return concatBytes(be(x, 64), be(y, 64)); };
/** scaas Schnorr (§1.9): R = kG, e = hashToScalar(keccak256(tag ‖ R ‖ Y ‖ m)), z = k + e·x. */
const schnorrScheme = (G, r, enc) => ({
  keyData: (sk) => enc(G.BASE.multiply(sk)),
  sign(sk, msg) {
    const k = (int(keccak_256(concatBytes(be(sk, 32), msg, utf8ToBytes('scaas.ua.vectors.nonce')))) % (r - 1n)) + 1n;
    const R = enc(G.BASE.multiply(k));
    const e = hashToScalar(keccak_256(concatBytes(SCHNORR_TAG, R, enc(G.BASE.multiply(sk)), msg)), r);
    if (e === 0n) throw new Error('e = 0');
    return concatBytes(R, be((k + e * sk) % r, 32));
  },
});

/** Port of ZetherCurves.sol `G1Bn254.mapToG1`: try-and-increment over keccak256(prefix ‖ uint32 ctr), even y. */
function mapToG1Bn254(prefix) {
  const { Fp } = BN;
  for (let ctr = 0; ; ctr++) {
    const x = int(keccak_256(concatBytes(prefix, be(BigInt(ctr), 4)))) % Fp.ORDER;
    const rhs = Fp.add(Fp.mul(Fp.sqr(x), x), 3n);
    let y = Fp.pow(rhs, (Fp.ORDER + 1n) / 4n);
    if (Fp.eql(Fp.sqr(y), rhs)) {
      if (y & 1n) y = Fp.ORDER - y;
      return bn254.G1.Point.fromAffine({ x, y });
    }
  }
}
const BN_LABEL = { sig: utf8ToBytes('SCAAS-UA-BLS-BN254-SIG-V1'), pop: utf8ToBytes('SCAAS-UA-BLS-BN254-POP-V1') };
const BLS_DST = { sig: 'SCAAS-UA-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_SIG_', pop: 'SCAAS-UA-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_' };
const bnG2enc = (P) => { const { x, y } = P.toAffine(); return concatBytes(be(x.c1, 32), be(x.c0, 32), be(y.c1, 32), be(y.c0, 32)); };
const blsG2enc = (P) => { const { x, y } = P.toAffine(); return concatBytes(be(x.c0, 64), be(x.c1, 64), be(y.c0, 64), be(y.c1, 64)); };

const SCHEMES = {
  'webauthn-p256': { kind: 0x0100, n: P256_N,
    keyData: (sk) => concatBytes(p256.getPublicKey(be(sk, 32), false).subarray(1), sha256(utf8ToBytes(RP_ID))),
    sign: (sk, m) => webauthnSign(sk, m) },
  p256: { kind: 0x0101, n: P256_N, keyData: (sk) => p256.getPublicKey(be(sk, 32), false).subarray(1),
    sign: (sk, m) => p256Sign(sk, sha256(m)) },
  bip340: { kind: 0x0103, n: SECP_N, keyData: (sk) => schnorr.getPublicKey(be(sk, 32)),
    sign: (sk, m) => schnorr.sign(m, be(sk, 32), ZERO32) },
  'schnorr-bn254': { kind: 0x0104, n: BN.Fr.ORDER, ...schnorrScheme(bn254.G1.Point, BN.Fr.ORDER, bnG1enc) },
  'schnorr-bls12381': { kind: 0x0105, n: BLS.Fr.ORDER, ...schnorrScheme(bls12_381.G1.Point, BLS.Fr.ORDER, blsG1enc) },
  'bls12381-minsig': { kind: 0x0106, n: BLS.Fr.ORDER, keyData: (sk) => blsG2enc(bls12_381.G2.Point.BASE.multiply(sk)),
    sign: (sk, m, { pop = false } = {}) => blsG1enc(bls12_381.G1.hashToCurve(m, { DST: pop ? BLS_DST.pop : BLS_DST.sig }).multiply(sk)) },
  'bls-bn254-minsig': { kind: 0x0107, n: BN.Fr.ORDER, keyData: (sk) => bnG2enc(bn254.G2.Point.BASE.multiply(sk)),
    sign: (sk, m, { pop = false } = {}) => bnG1enc(mapToG1Bn254(concatBytes(pop ? BN_LABEL.pop : BN_LABEL.sig, m)).multiply(sk)) },
};
// a sibling kind whose tag a "wrong-kind-tag" negative signs under (same curve where one exists)
const OTHER_KIND = { 0x0100: 0x0101, 0x0101: 0x0100, 0x0103: 0x0110, 0x0104: 0x0140, 0x0105: 0x0141, 0x0106: 0x0105, 0x0107: 0x0104 };

/** First point on y² = x³ + 4 (x = 1, 2, …) outside the BLS12-381 G1 subgroup. */
function blsG1OffSubgroup() {
  const { Fp } = BLS;
  for (let x = 1n; ; x++) {
    let y;
    try { y = Fp.sqrt(Fp.add(Fp.mul(Fp.sqr(x), x), 4n)); } catch { continue; }
    const P = bls12_381.G1.Point.fromAffine({ x, y });
    try { P.assertValidity(); } catch { return blsG1enc(P); }
  }
}

// --- derived rows ---
const popOf = (kind, uaId, ctx) => {
  const popDigest = ua.popDigest({ ...contexts[ctx], ua: uaId });
  return { popDigest, message: ua.uaMessage(kind, ua.POP_TAG, popDigest) };
};
const derivedRows = Object.entries(SCHEMES).map(([name, s]) => {
  const sk = secretOf(name, s.n);
  const keyData = s.keyData(sk);
  const id = ua.deriveUA(s.kind, keyData);
  const sign = (m, o) => s.sign(sk, m, o);
  const pop = (ctx) => { const p = popOf(s.kind, id, ctx); return { context: ctx, popDigest: hex(p.popDigest), message: hex(p.message), sig: hex(sign(p.message, { pop: true })) }; };
  const metatx = ua.uaMessage(s.kind, tag('metatx'), DIGEST);
  const member = ua.uaMessage(s.kind, tag('member'), DIGEST);
  const metatxSig = sign(metatx);
  const sigs = [
    { purpose: 'metatx', purposeTag: hex(tag('metatx')), digest: hex(DIGEST), message: hex(metatx), sig: hex(metatxSig) },
    { purpose: 'member', purposeTag: hex(tag('member')), digest: hex(DIGEST), message: hex(member), sig: hex(sign(member)) },
  ];
  const popA = popOf(s.kind, id, 'A').message;
  const popB = popOf(s.kind, id, 'B').message;
  const neg = (n, verifyPop, message, sig) => ({ name: n, verifyPop, message: hex(message), sig: hex(sig) });
  const negatives = [
    neg('wrong-purpose', false, member, metatxSig),
    neg('wrong-kind-tag', false, metatx, sign(ua.uaMessage(OTHER_KIND[s.kind], tag('metatx'), DIGEST))),
    neg('other-chain-uid', true, popB, sign(popOf(s.kind, id, 'C').message, { pop: true })), // B and C: both evm:7622
    neg('other-registry', true, popA, sign(popOf(s.kind, id, 'D').message, { pop: true })),
    neg('pop-as-sig', false, metatx, sign(popA, { pop: true })),
  ];
  if (s.kind === 0x0100) {
    const wa = (o) => webauthnSign(sk, metatx, o);
    sigs.push({ ...sigs[0], variant: 'crossOrigin-false', sig: hex(wa({ tail: ',"crossOrigin":false' })) },
      { ...sigs[0], variant: 'crossOrigin-false-extra', sig: hex(wa({ tail: `,"crossOrigin":false${CHROME_EXTRA}` })) });
    negatives.push(neg('mutated', false, metatx, flip(metatxSig, 0x5f)), neg('high-s', false, metatx, webauthnHighS(metatxSig)),
      neg('no-uv', false, metatx, wa({ flags: 0x01 })), neg('no-up', false, metatx, wa({ flags: 0x04 })),
      neg('cross-origin-true', false, metatx, wa({ tail: ',"crossOrigin":true' })),
      neg('extra-without-cross-origin', false, metatx, wa({ tail: CHROME_EXTRA })),
      neg('wrong-rp-id', false, metatx, wa({ rpId: 'other.example' })), neg('type-create', false, metatx, wa({ type: 'webauthn.create' })));
  } else {
    negatives.push(neg('mutated', false, metatx, flip(metatxSig, metatxSig.length - 1)));
  }
  if (s.kind === 0x0101) negatives.push(neg('high-s', false, metatx, highS(metatxSig)));
  if (s.kind === 0x0104 || s.kind === 0x0105) {
    const p = metatxSig.length - 32;
    const r = s.n;
    negatives.push(neg('z-not-reduced', false, metatx, concatBytes(metatxSig.subarray(0, p), be(int(metatxSig.subarray(p)) + r, 32))));
  }
  if (s.kind === 0x0106 || s.kind === 0x0107) {
    negatives.push(neg('sig-dst-as-pop', true, popA, sign(popA)), neg('pop-dst-as-sig', false, metatx, sign(metatx, { pop: true })),
      neg('identity', false, metatx, new Uint8Array(metatxSig.length)));
  }
  if (s.kind === 0x0106) negatives.push(neg('off-subgroup', false, metatx, blsG1OffSubgroup()));
  return { name, kind: s.kind, secret: hex(be(sk, 32)), keyData: hex(keyData), ua: hex(id), pop: pop('A'), popOther: pop('B'),
    sigs, negatives };
});

// --- native EOA: UAAuth under the registry domain ---
const ecdsa = (sk, h) => {
  const rec = secp256k1.sign(h, be(sk, 32), { prehash: false, lowS: true, format: 'recovered' });
  return concatBytes(rec.subarray(1), Uint8Array.of(27 + rec[0]));
};
const nativeSk = secretOf('native', SECP_N);
const nativeAddr = keccak_256(secp256k1.getPublicKey(be(nativeSk, 32), false).subarray(1)).subarray(12);
const nativeUa = ua.nativeId(0x0001, nativeAddr);
const domain = (ctx, generation) => ({ generation, ...contexts[ctx] });
const authDigest = (ctx, gen, id, p, d) => ua.uaAuthDigest(domain(ctx, gen), id, tag(p), d);
const nativeSigs = [['A', 1, 'metatx'], ['A', 1, 'member'], ['A', 2, 'metatx'], ['B', 1, 'metatx']].map(([context, generation, purpose]) => {
  const h = authDigest(context, generation, nativeUa, purpose, DIGEST);
  return { context, generation, purpose, digest: hex(DIGEST), uaAuthDigest: hex(h), sig: hex(ecdsa(nativeSk, h)) };
});
const goodA = fromHex(nativeSigs[0].sig);
const nativeHighS = concatBytes(goodA.subarray(0, 32), be(SECP_N - int(goodA.subarray(32, 64)), 32), Uint8Array.of(goodA[64] ^ 1));
const nativeNeg = (name, sig) => ({ name, context: 'A', generation: 1, purpose: 'metatx', digest: hex(DIGEST), sig: hex(sig) });
const nativeNegatives = [
  nativeNeg('raw-digest', ecdsa(nativeSk, DIGEST)),
  nativeNeg('other-generation', fromHex(nativeSigs[2].sig)),
  nativeNeg('other-registry', ecdsa(nativeSk, authDigest('D', 1, nativeUa, 'metatx', DIGEST))),
  nativeNeg('wrong-purpose', fromHex(nativeSigs[1].sig)),
  nativeNeg('high-s', nativeHighS),
];

// --- msig: native(1), p256(1), bls-bn254-minsig(1), schnorr-bn254(2); threshold 3 ---
const row = (name) => derivedRows.find((r) => r.name === name);
const cmp = (a, b) => { for (let i = 0; i < 32; i++) if (a[i] !== b[i]) return a[i] - b[i]; return 0; };
const members = [
  { kind: 0x0001, name: 'native', id: nativeUa, weight: 1 },
  ...[['p256', 1], ['bls-bn254-minsig', 1], ['schnorr-bn254', 2]].map(([name, weight]) => ({ kind: SCHEMES[name].kind, name, id: fromHex(row(name).ua), weight })),
].sort((a, b) => cmp(a.id, b.id)).map((m, index) => ({ ...m, index }));
const THRESHOLD = 3;
const msigKey = ua.encodeMsig(THRESHOLD, members);
const msigUa = ua.deriveUA(0x0120, msigKey);
const msigPurpose = 'metatx';
const memberDigest = ua.memberDigest(msigUa, ua.uaMessage(0x0120, tag(msigPurpose), DIGEST));
const byName = Object.fromEntries(members.map((m) => [m.name, m]));
/** One MemberSig {index, keyData, sig}: native over UAAuth(id, member, member_digest) in context A gen 1, derived via its scheme. */
function memberSig(name, { raw = false, secretName } = {}) {
  const m = byName[name];
  if (m.kind === 0x0001) {
    return { index: m.index, keyData: new Uint8Array(0), sig: ecdsa(nativeSk, raw ? memberDigest : authDigest('A', 1, m.id, 'member', memberDigest)) };
  }
  const s = SCHEMES[name];
  const sk = secretOf(secretName ?? name, s.n);
  return { index: m.index, keyData: s.keyData(sk), sig: s.sign(sk, ua.uaMessage(m.kind, tag('member'), memberDigest)) };
}
/** `abi.encode(MemberSig[])`, MemberSig = (uint16 index, bytes keyData, bytes sig). */
function encodeMemberSigs(list) {
  const tuples = list.map(({ index, keyData, sig }) => abiEncode(['uint16', 'bytes', 'bytes'], [index, keyData, sig]));
  const offsets = [];
  let o = 32 * list.length;
  for (const t of tuples) { offsets.push(word(o)); o += t.length; }
  return concatBytes(word(32), word(list.length), ...offsets, ...tuples);
}
const byIndex = (list) => [...list].sort((a, b) => a.index - b.index);
const set = (name, valid, list) => {
  const sig = encodeMemberSigs(list);
  return { name, valid, purpose: msigPurpose, digest: hex(DIGEST), memberDigest: hex(memberDigest), indices: list.map((s) => s.index),
    sig: hex(sig), auth: hex(abiEncode(['bytes', 'bytes'], [msigKey, sig])) };
};
const S = (n, o) => memberSig(n, o);
const sets = [
  set('at-threshold', true, byIndex([S('native'), S('schnorr-bn254')])),
  set('at-threshold-three', true, byIndex([S('native'), S('p256'), S('bls-bn254-minsig')])),
  set('extra-after-threshold', false, byIndex(members.map((m) => S(m.name)))),
  set('below-threshold', false, byIndex([S('native'), S('p256')])),
  set('unsorted', false, byIndex([S('native'), S('schnorr-bn254')]).reverse()),
  set('duplicate', false, byIndex([S('native'), S('native'), S('p256')])),
  set('wrong-member-key', false, byIndex([S('native'), S('p256', { secretName: 'p256-other' }), S('bls-bn254-minsig')])),
  set('native-raw-digest', false, byIndex([S('native', { raw: true }), S('schnorr-bn254')])),
];

// --- BIP-340 official test vectors (bip-0340/test-vectors.csv), the 32-byte-message cases 0–14 ---
const BIP340_A = 'dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659';
const BIP340_M = '243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89';
const bip340Official = [
  [0, 'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9', '00'.repeat(32),
    'e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0', true, ''],
  [1, BIP340_A, BIP340_M,
    '6896bd60eeae296db48a229ff71dfe071bde413e6d43f917dc8dcf8c78de33418906d11ac976abccb20b091292bff4ea897efcb639ea871cfa95f6de339e4b0a', true, ''],
  [2, 'dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8', '7e2d58d8b3bcdf1abadec7829054f90dda9805aab56c77333024b9d0a508b75c',
    '5831aaeed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1bab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7', true, ''],
  [3, '25d1dff95105f5253c4022f628a996ad3a0d95fbf21d468a1b33f8c160d8f517', 'ff'.repeat(32),
    '7eb0509757e246f19449885651611cb965ecc1a187dd51b64fda1edc9637d5ec97582b9cb13db3933705b32ba982af5af25fd78881ebb32771fc5922efc66ea3', true, 'test fails if msg is reduced modulo p or n'],
  [4, 'd69c3509bb99e412e68b0fe8544e72837dfa30746d8be2aa65975f29d22dc7b9', '4df3c3f68fcc83b27e9d42c90431a72499f17875c81a599b566c9889b9696703',
    '00000000000000000000003b78ce563f89a0ed9414f5aa28ad0d96d6795f9c6376afb1548af603b3eb45c9f8207dee1060cb71c04e80f593060b07d28308d7f4', true, ''],
  [5, 'eefdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34', BIP340_M,
    '6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e17776969e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b', false, 'public key not on the curve'],
  [6, BIP340_A, BIP340_M,
    'fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a14602975563cc27944640ac607cd107ae10923d9ef7a73c643e166be5ebeafa34b1ac553e2', false, 'has_even_y(R) is false'],
  [7, BIP340_A, BIP340_M,
    '1fa62e331edbc21c394792d2ab1100a7b432b013df3f6ff4f99fcb33e0e1515f28890b3edb6e7189b630448b515ce4f8622a954cfe545735aaea5134fccdb2bd', false, 'negated message'],
  [8, BIP340_A, BIP340_M,
    '6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e177769961764b3aa9b2ffcb6ef947b6887a226e8d7c93e00c5ed0c1834ff0d0c2e6da6', false, 'negated s value'],
  [9, BIP340_A, BIP340_M,
    '0000000000000000000000000000000000000000000000000000000000000000123dda8328af9c23a94c1feecfd123ba4fb73476f0d594dcb65c6425bd186051', false, 'sG - eP is infinite (x(inf) as 0)'],
  [10, BIP340_A, BIP340_M,
    '00000000000000000000000000000000000000000000000000000000000000017615fbaf5ae28864013c099742deadb4dba87f11ac6754f93780d5a1837cf197', false, 'sG - eP is infinite (x(inf) as 1)'],
  [11, BIP340_A, BIP340_M,
    '4a298dacae57395a15d0795ddbfd1dcb564da82b0f269bc70a74f8220429ba1d69e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b', false, 'sig[0:32] is not an X coordinate on the curve'],
  [12, BIP340_A, BIP340_M,
    'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f69e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b', false, 'sig[0:32] is equal to the field size'],
  [13, BIP340_A, BIP340_M,
    '6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e177769fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141', false, 'sig[32:64] is equal to the curve order'],
  [14, 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30', BIP340_M,
    '6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e17776969e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b', false, 'public key exceeds the field size'],
].map(([index, publicKey, message, signature, valid, comment]) => {
  let ok;
  try { ok = schnorr.verify(fromHex(signature), fromHex(message), fromHex(publicKey)); } catch { ok = false; }
  if (ok !== valid) throw new Error(`BIP-340 vector ${index}: noble says ${ok}`);
  return { index, publicKey: `0x${publicKey}`, message: `0x${message}`, sig: `0x${signature}`, valid, comment };
});

// --- write ---
const note = 'Generated by clients/clientkeys/scripts/ua-sig-vectors.mjs (src/ua.js on @noble/curves 2.4.0); never edit by hand. '
  + 'Every positive must verify and every negative must fail (verifyPop: which verifier entry point is asked). '
  + 'The scaas Schnorr transcript and the bn254 mapToG1 have no independent second implementation: clients/scaas-ua agreeing '
  + 'on them is self-consistency only (accounts.md §1.16). msig auth = abi.encode(bytes keyData, bytes sig) (§1.9).';
const out = {
  note, version: 1, context: 'A', contextOther: 'B', contexts: { A: contexts.A, B: contexts.B, C: contexts.C, D: contexts.D },
  digest: hex(DIGEST), derived: derivedRows, bip340Official,
  native: { secret: hex(be(nativeSk, 32)), address: hex(nativeAddr), ua: hex(nativeUa), sigs: nativeSigs, negatives: nativeNegatives },
  msig: { keyData: hex(msigKey), ua: hex(msigUa), threshold: THRESHOLD, context: 'A', generation: 1,
    members: members.map((m) => ({ index: m.index, kind: m.kind, name: m.name, id: hex(m.id), weight: m.weight, secretRef: m.name })),
    sets },
};
mkdirSync(OUT, { recursive: true });
writeFileSync(join(OUT, 'signatures.json'), `${JSON.stringify(out, null, 2)}\n`);
const negs = derivedRows.reduce((n, r) => n + r.negatives.length, 0);
console.log(`signatures.json: ${derivedRows.length} derived kinds (${negs} negatives), native ${nativeSigs.length}+${nativeNegatives.length}, msig ${sets.length} sets, ${bip340Official.length} BIP-340 official; written to ${OUT}`);
```

- [ ] **Step 2: Node re-verification.** Create `clients/clientkeys/test/ua-sig.test.js`:

```js
// smartcontracts/vectors/ua/signatures.json (UA-2a): the generator reproduces it byte for byte, and every row is re-verified
// here with noble through verifiers written from accounts.md §1.9 (not the generator's signing code): positives pass,
// negatives fail, msig sets give their stated verdict.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { p256 } from '@noble/curves/nist.js';
import { secp256k1, schnorr } from '@noble/curves/secp256k1.js';
import { bn254 } from '@noble/curves/bn254.js';
import { bls12_381 } from '@noble/curves/bls12-381.js';
import { sha256 } from '@noble/hashes/sha2.js';
import * as ua from '../src/ua.js';
import { hex, fromHex, keccak_256, utf8ToBytes, concatBytes, b64url } from '../src/bytes.js';

const dir = new URL('../../../smartcontracts/vectors/ua/', import.meta.url);
const V = JSON.parse(readFileSync(new URL('signatures.json', dir)));
const int = (b) => BigInt(hex(b));
const B = (h) => fromHex(h);
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const tag = (p) => ua.purposeTag(p);
const attempt = (f) => { try { return f(); } catch { return false; } };

test('the generator reproduces signatures.json byte for byte', () => {
  const out = mkdtempSync(join(tmpdir(), 'ua-sig-vectors-'));
  try {
    const r = spawnSync(process.execPath, [fileURLToPath(new URL('../scripts/ua-sig-vectors.mjs', import.meta.url)), out], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    assert.equal(readFileSync(join(out, 'signatures.json'), 'utf8'), readFileSync(new URL('signatures.json', dir), 'utf8'));
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
});

// --- ABI reading (offsets as the decoder sees them) ---
const wordAt = (b, o) => Number(int(b.subarray(o, o + 32)));
const bytesAt = (b, base, head) => { const o = base + wordAt(b, head); return b.subarray(o + 32, o + 32 + wordAt(b, o)); };

// --- verifiers (§1.9) ---
const P256_N = p256.Point.Fn.ORDER;
const p256Ok = (xy, h, r, s) => int(s) <= P256_N / 2n
  && p256.verify(concatBytes(r, s), h, concatBytes(Uint8Array.of(4), xy), { prehash: false, lowS: true });

/** SmartKeyAccount._clientDataOk without the origin comparison. */
function clientDataOk(cd, challenge) {
  const prefix = `{"type":"webauthn.get","challenge":"${b64url(challenge)}","origin":"`;
  const s = new TextDecoder().decode(cd);
  const n = s.length;
  if (n < prefix.length + 2 || !s.startsWith(prefix)) return false;
  const end = s.indexOf('"', prefix.length);
  if (end < 0 || end + 1 >= n) return false;
  if (s[end + 1] === '}') return end + 2 === n;
  const cross = ',"crossOrigin":false';
  const after = end + 1 + cross.length;
  if (after >= n || s.slice(end + 1, after) !== cross) return false;
  return s[after] === '}' ? after + 1 === n : s[after] === ',';
}
function webauthnOk(kd, msg, blob) {
  const authData = bytesAt(blob, 0, 0);
  const cd = bytesAt(blob, 0, 32);
  if (authData.length < 37 || !eq(authData.subarray(0, 32), kd.subarray(64, 96)) || (authData[32] & 0x05) !== 0x05) return false;
  if (!clientDataOk(cd, msg)) return false;
  return p256Ok(kd.subarray(0, 64), sha256(concatBytes(authData, sha256(cd))), blob.subarray(64, 96), blob.subarray(96, 128));
}

const hashToScalar = (seed, r) => ((int(keccak_256(concatBytes(seed, Uint8Array.of(2)))) << 256n)
  + int(keccak_256(concatBytes(seed, Uint8Array.of(3))))) % r;
const bnG1 = (b) => {
  const x = int(b.subarray(0, 32)); const y = int(b.subarray(32, 64));
  if (x === 0n && y === 0n) throw new Error('identity');
  const P = bn254.G1.Point.fromAffine({ x, y }); P.assertValidity(); return P;
};
const blsFp = (b) => { if (!b.subarray(0, 16).every((v) => v === 0)) throw new Error('padding'); return int(b.subarray(16, 64)); };
const blsG1 = (b) => {
  const x = blsFp(b.subarray(0, 64)); const y = blsFp(b.subarray(64, 128));
  if (x === 0n && y === 0n) throw new Error('identity');
  const P = bls12_381.G1.Point.fromAffine({ x, y }); P.assertValidity(); return P; // assertValidity includes the subgroup
};
const schnorrOk = (G, r, size, dec) => (kd, msg, sig) => {
  if (sig.length !== size + 32) return false;
  const Rb = sig.subarray(0, size);
  const z = int(sig.subarray(size));
  const R = dec(Rb); const Y = dec(kd);
  const e = hashToScalar(keccak_256(concatBytes(utf8ToBytes('scaas.ua.schnorr.v1'), Rb, kd, msg)), r);
  if (z >= r || e === 0n) return false;
  return G.BASE.multiplyUnsafe(z).equals(R.add(Y.multiply(e)));
};

function mapToG1Bn254(prefix) {
  const { Fp } = bn254.fields;
  for (let ctr = 0; ; ctr++) {
    const c = new Uint8Array(4); new DataView(c.buffer).setUint32(0, ctr);
    const x = int(keccak_256(concatBytes(prefix, c))) % Fp.ORDER;
    const rhs = Fp.add(Fp.mul(Fp.sqr(x), x), 3n);
    let y = Fp.pow(rhs, (Fp.ORDER + 1n) / 4n);
    if (Fp.eql(Fp.sqr(y), rhs)) return bn254.G1.Point.fromAffine({ x, y: y & 1n ? Fp.ORDER - y : y });
  }
}
const pairingEq = (curve, a, b, c, d) => curve.fields.Fp12.eql(curve.pairing(a, b), curve.pairing(c, d));
function blsBn254Ok(kd, msg, sig, pop) {
  if (sig.length !== 64) return false;
  const S = bnG1(sig);
  const w = [0, 1, 2, 3].map((i) => int(kd.subarray(32 * i, 32 * i + 32)));
  const pk = bn254.G2.Point.fromAffine({ x: { c0: w[1], c1: w[0] }, y: { c0: w[3], c1: w[2] } });
  const H = mapToG1Bn254(concatBytes(utf8ToBytes(pop ? 'SCAAS-UA-BLS-BN254-POP-V1' : 'SCAAS-UA-BLS-BN254-SIG-V1'), msg));
  return pairingEq(bn254, S, bn254.G2.Point.BASE, H, pk);
}
function bls12381Ok(kd, msg, sig, pop) {
  if (sig.length !== 128) return false;
  const S = blsG1(sig);
  const w = [0, 1, 2, 3].map((i) => blsFp(kd.subarray(64 * i, 64 * i + 64)));
  const pk = bls12_381.G2.Point.fromAffine({ x: { c0: w[0], c1: w[1] }, y: { c0: w[2], c1: w[3] } });
  const H = bls12_381.G1.hashToCurve(msg, { DST: `SCAAS-UA-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_${pop ? 'POP' : 'SIG'}_` });
  return pairingEq(bls12_381, S, bls12_381.G2.Point.BASE, H, pk);
}
const VERIFY = {
  0x0100: webauthnOk,
  0x0101: (kd, msg, sig) => sig.length === 64 && p256Ok(kd, sha256(msg), sig.subarray(0, 32), sig.subarray(32)),
  0x0103: (kd, msg, sig) => sig.length === 64 && schnorr.verify(sig, msg, kd),
  0x0104: schnorrOk(bn254.G1.Point, bn254.fields.Fr.ORDER, 64, bnG1),
  0x0105: schnorrOk(bls12_381.G1.Point, bls12_381.fields.Fr.ORDER, 128, blsG1),
  0x0106: bls12381Ok,
  0x0107: blsBn254Ok,
};
/** `verify` / `verifyPop` (pop only matters for the BLS kinds); any throw is a refusal. */
const verify = (kind, kd, msg, sig, pop = false) => attempt(() => VERIFY[kind](B(kd), B(msg), B(sig), pop) === true);

const SECP_N = secp256k1.Point.Fn.ORDER;
/** Native EOA: low-s ECDSA r‖s‖v over UAAuth(ua, purpose, digest) under the registry domain. */
function nativeOk(address, h, sig) {
  return attempt(() => {
    const s = B(sig);
    if (s.length !== 65 || (s[64] !== 27 && s[64] !== 28) || int(s.subarray(32, 64)) > SECP_N / 2n) return false;
    const pub = secp256k1.recoverPublicKey(concatBytes(Uint8Array.of(s[64] - 27), s.subarray(0, 64)), h, { prehash: false });
    return eq(keccak_256(secp256k1.Point.fromBytes(pub).toBytes(false).subarray(1)).subarray(12), B(address));
  });
}
const domain = (ctx, generation) => ({ generation, ...V.contexts[ctx] });

test('derived kinds: key data, ids, PoP messages, every signature verifies', () => {
  assert.equal(V.derived.length, 7);
  for (const r of V.derived) {
    const kd = B(r.keyData);
    assert.equal(hex(ua.deriveUA(r.kind, kd)), r.ua, r.name);
    for (const p of [r.pop, r.popOther]) {
      const d = ua.popDigest({ ...V.contexts[p.context], ua: B(r.ua) });
      assert.equal(hex(d), p.popDigest, `${r.name} popDigest ${p.context}`);
      assert.equal(hex(ua.uaMessage(r.kind, ua.POP_TAG, d)), p.message);
      assert.ok(verify(r.kind, r.keyData, p.message, p.sig, true), `${r.name} pop ${p.context}`);
    }
    for (const s of r.sigs) {
      assert.equal(hex(ua.uaMessage(r.kind, tag(s.purpose), B(s.digest))), s.message);
      assert.ok(verify(r.kind, r.keyData, s.message, s.sig), `${r.name} ${s.purpose} ${s.variant ?? ''}`);
    }
  }
});

test('derived kinds: every negative fails', () => {
  for (const r of V.derived) {
    assert.ok(r.negatives.length >= 6, r.name);
    for (const n of r.negatives) assert.equal(verify(r.kind, r.keyData, n.message, n.sig, n.verifyPop), false, `${r.name} ${n.name}`);
  }
});

test('native EOA: UAAuth signatures verify, negatives fail', () => {
  const N = V.native;
  assert.equal(hex(ua.nativeId(0x0001, B(N.address))), N.ua);
  for (const s of N.sigs) {
    const h = ua.uaAuthDigest(domain(s.context, s.generation), B(N.ua), tag(s.purpose), B(s.digest));
    assert.equal(hex(h), s.uaAuthDigest);
    assert.ok(nativeOk(N.address, h, s.sig), `${s.context} ${s.generation} ${s.purpose}`);
  }
  for (const n of N.negatives) {
    const h = ua.uaAuthDigest(domain(n.context, n.generation), B(N.ua), tag(n.purpose), B(n.digest));
    assert.equal(nativeOk(N.address, h, n.sig), false, n.name);
  }
});

/** The registry's msig path (§1.9): auth = abi.encode(bytes keyData, bytes abi.encode(MemberSig[])). */
function msigOk(structureUa, purposeTag, digest, auth) {
  return attempt(() => {
    const keyData = bytesAt(auth, 0, 0);
    const sigs = bytesAt(auth, 0, 32);
    if (!eq(ua.uaOf(0x0120, keyData), structureUa)) return false;
    const threshold = (keyData[0] << 8) | keyData[1];
    const count = (keyData[2] << 8) | keyData[3];
    const md = ua.memberDigest(structureUa, ua.uaMessage(0x0120, purposeTag, digest));
    const a = wordAt(sigs, 0);
    const n = wordAt(sigs, a);
    const base = a + 32; // element offsets are relative to here
    let sum = 0;
    let last = -1;
    for (let i = 0; i < n; i++) {
      if (sum >= threshold) return false; // stops at the threshold
      const t = base + wordAt(sigs, base + 32 * i);
      const index = wordAt(sigs, t);
      if (index <= last || index >= count) return false;
      last = index;
      const o = 4 + 36 * index;
      const kind = (keyData[o] << 8) | keyData[o + 1];
      const id = keyData.subarray(o + 2, o + 34);
      const weight = (keyData[o + 34] << 8) | keyData[o + 35];
      const mkd = bytesAt(sigs, t, t + 32);
      const sig = bytesAt(sigs, t, t + 64);
      const ok = ua.isNativeKind(kind)
        ? nativeOk(hex(id.subarray(12)), ua.uaAuthDigest(domain(V.msig.context, V.msig.generation), id, tag('member'), md), hex(sig))
        : eq(ua.uaOf(kind, mkd), id) && verify(kind, hex(mkd), hex(ua.uaMessage(kind, tag('member'), md)), hex(sig));
      if (!ok) return false;
      sum += weight;
    }
    return sum >= threshold;
  });
}

test('msig: structure id, members, every set gives its verdict', () => {
  const M = V.msig;
  const members = M.members.map((m) => ({ kind: m.kind, id: B(m.id), weight: m.weight }));
  assert.equal(hex(ua.encodeMsig(M.threshold, members)), M.keyData);
  assert.equal(hex(ua.deriveUA(0x0120, B(M.keyData))), M.ua);
  for (const m of M.members) {
    const id = m.kind === 1 ? V.native.ua : V.derived.find((r) => r.name === m.secretRef).ua;
    assert.equal(m.id, id, m.name);
  }
  for (const s of M.sets) {
    assert.equal(hex(ua.memberDigest(B(M.ua), ua.uaMessage(0x0120, tag(s.purpose), B(s.digest)))), s.memberDigest);
    assert.equal(msigOk(B(M.ua), tag(s.purpose), B(s.digest), B(s.auth)), s.valid, s.name);
  }
  assert.ok(M.sets.filter((s) => s.valid).length >= 2);
});

test('BIP-340 official vectors (32-byte messages) give their verdict', () => {
  assert.equal(V.bip340Official.length, 15);
  for (const t of V.bip340Official) assert.equal(verify(0x0103, t.publicKey, t.message, t.sig), t.valid, `vector ${t.index}`);
});
```

- [ ] **Step 3: Generate.** `cd clients/clientkeys && ../../scripts/capped node scripts/ua-sig-vectors.mjs` — prints
  `signatures.json: 7 derived kinds (59 negatives), native 4+5, msig 9 sets, 15 BIP-340 official; written to …/smartcontracts/vectors/ua/`.
  The file is 106 940 bytes; its sha256 must be `93fa6bd174ebb857f67dbf117dfa6e82270f6db425d83b92cd8560ffd7df58a8`
  (after the final review's `native-member-keydata` set; `de2f91d66719311fdffc8deb34d58f8d55e352324c8bdff104a0038f88d8602c`
  after the native high-s fix; the spike run on 2026-10-12 produced `771e7c5e…` with 8 sets).

- [ ] **Step 4: Rust verify module.** Create `clients/scaas-ua/src/verify.rs`:

```rust
//! UA-2a signature verification (accounts.md §1.9) on curve code independent of the JS generator: p256 (P-256, WebAuthn),
//! k256 (BIP-340, native ECDSA), arkworks (scaas Schnorr on bn254 / BLS12-381; BLS min-sig on both curves, with an own
//! port of the bn254 `mapToG1` and arkworks' RFC 9380 hasher for BLS12-381). Key data is assumed validated
//! ([`crate::validate_key_data`]) and matched against the id; signatures are untrusted: anything malformed is `false`,
//! never a panic. UNAUDITED.
use crate::keccak;
use ark_ec::hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve};
use ark_ec::pairing::Pairing;
use ark_ec::short_weierstrass::{Affine, SWCurveConfig};
use ark_ec::AffineRepr;
use ark_ff::field_hashers::DefaultFieldHasher;
use ark_ff::{BigInteger, Field, PrimeField, Zero};
use sha2::{Digest, Sha256};

pub const SCHNORR_TAG: &[u8] = b"scaas.ua.schnorr.v1";
pub const BLS12381_DST_SIG: &[u8] = b"SCAAS-UA-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_SIG_";
pub const BLS12381_DST_POP: &[u8] = b"SCAAS-UA-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
pub const BN254_LABEL_SIG: &[u8] = b"SCAAS-UA-BLS-BN254-SIG-V1";
pub const BN254_LABEL_POP: &[u8] = b"SCAAS-UA-BLS-BN254-POP-V1";

/// `IUAKindVerifier.verify` (`pop = false`) / `IUAPopVerifier.verifyPop` (`pop = true`) for the UA-2a kinds; `pop` only
/// changes the BLS kinds' domain. Other kinds: `false`.
pub fn verify(kind: u16, key_data: &[u8], message: &[u8; 32], sig: &[u8], pop: bool) -> bool {
    match kind {
        0x0100 => webauthn_p256(key_data, message, sig),
        0x0101 => sig.len() == 64 && key_data.len() == 64 && p256_ok(key_data, &sha256(&[message]), sig),
        0x0103 => bip340(key_data, message, sig),
        0x0104 => schnorr::<ark_bn254::g1::Config>(key_data, message, sig, 32),
        0x0105 => schnorr::<ark_bls12_381::g1::Config>(key_data, message, sig, 64),
        0x0106 => bls12381_minsig(key_data, message, sig, pop),
        0x0107 => bls_bn254_minsig(key_data, message, sig, pop),
        _ => false,
    }
}

/// A native EOA: low-s ECDSA `r ‖ s ‖ v` (v ∈ {27, 28}) over `digest` (the registry's `uaAuthDigest`) recovering `address`.
pub fn native_ecdsa(address: &[u8; 20], digest: &[u8; 32], sig: &[u8]) -> bool {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    if sig.len() != 65 || !(sig[64] == 27 || sig[64] == 28) {
        return false;
    }
    let Ok(s) = Signature::from_slice(&sig[..64]) else { return false };
    if s.normalize_s().is_some() {
        return false; // high s
    }
    let Some(rec) = RecoveryId::from_byte(sig[64] - 27) else { return false };
    let Ok(vk) = VerifyingKey::recover_from_prehash(digest, &s, rec) else { return false };
    let pt = vk.to_encoded_point(false);
    keccak(&[&pt.as_bytes()[1..]])[12..] == address[..]
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// ECDSA-P256 over the 32-byte `hash`, `xy` the uncompressed key without its prefix; high s refused.
fn p256_ok(xy: &[u8], hash: &[u8; 32], rs: &[u8]) -> bool {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    let mut sec1 = [4u8; 65];
    sec1[1..].copy_from_slice(xy);
    let (Ok(vk), Ok(s)) = (VerifyingKey::from_sec1_bytes(&sec1), Signature::from_slice(rs)) else { return false };
    s.normalize_s().is_none() && vk.verify_prehash(hash, &s).is_ok()
}

// --- WebAuthn ---

fn word_usize(b: &[u8], o: usize) -> Option<usize> {
    let w = b.get(o..o.checked_add(32)?)?;
    w[..24].iter().all(|x| *x == 0).then(|| w[24..].iter().fold(0usize, |a, x| (a << 8) | *x as usize))
}
/// The dynamic `bytes` whose offset (relative to `base`) sits at `head`.
fn abi_bytes(b: &[u8], base: usize, head: usize) -> Option<&[u8]> {
    let o = base.checked_add(word_usize(b, head)?)?;
    let n = word_usize(b, o)?;
    b.get(o + 32..(o + 32).checked_add(n)?)
}

fn base64url(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = c.iter().enumerate().fold(0u32, |a, (i, x)| a | (*x as u32) << (16 - 8 * i));
        for i in 0..=c.len() {
            out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

/// `SmartKeyAccount._clientDataOk` without the origin comparison: the fixed prefix with type and challenge, any origin up
/// to the next `"`, then `}` at the end, or `,"crossOrigin":false` followed by `}` at the end or by `,`.
fn client_data_ok(cd: &[u8], challenge: &[u8; 32]) -> bool {
    let prefix = format!("{{\"type\":\"webauthn.get\",\"challenge\":\"{}\",\"origin\":\"", base64url(challenge));
    let (p, n) = (prefix.len(), cd.len());
    if n < p + 2 || &cd[..p] != prefix.as_bytes() {
        return false;
    }
    let Some(end) = cd[p..].iter().position(|c| *c == b'"').map(|i| p + i) else { return false };
    if end + 1 >= n {
        return false;
    }
    if cd[end + 1] == b'}' {
        return end + 2 == n;
    }
    let cross = b",\"crossOrigin\":false";
    let after = end + 1 + cross.len();
    if after >= n || &cd[end + 1..after] != cross {
        return false;
    }
    if cd[after] == b'}' { after + 1 == n } else { cd[after] == b',' }
}

/// `abi.encode(bytes authenticatorData, string clientDataJSON, uint256 r, uint256 s)`.
fn webauthn_p256(key_data: &[u8], message: &[u8; 32], sig: &[u8]) -> bool {
    let (Some(auth), Some(cd)) = (abi_bytes(sig, 0, 0), abi_bytes(sig, 0, 32)) else { return false };
    if key_data.len() != 96 || sig.len() < 128 || auth.len() < 37 || auth[..32] != key_data[64..96] || auth[32] & 0x05 != 0x05 {
        return false;
    }
    client_data_ok(cd, message) && p256_ok(&key_data[..64], &sha256(&[auth, &sha256(&[cd])]), &sig[64..128])
}

// --- BIP-340 ---

fn bip340(key_data: &[u8], message: &[u8; 32], sig: &[u8]) -> bool {
    let (Ok(vk), Ok(s)) = (k256::schnorr::VerifyingKey::from_bytes(key_data), k256::schnorr::Signature::try_from(sig)) else {
        return false;
    };
    vk.verify_raw(message, &s).is_ok()
}

// --- arkworks points ---

/// Big-endian bytes → the element, `None` unless canonical (< modulus).
fn fe<F: PrimeField>(b: &[u8]) -> Option<F> {
    let f = F::from_be_bytes_mod_order(b);
    (f.into_bigint().to_bytes_be() == b).then_some(f)
}
/// A coordinate `w` bytes wide: bn254 32, BLS12-381 64 (16 zero bytes, then 48).
fn coord<F: PrimeField>(b: &[u8], w: usize) -> Option<F> {
    if w == 64 && b[..16].iter().any(|x| *x != 0) {
        return None;
    }
    fe(&b[w - F::MODULUS.to_bytes_be().len()..w])
}
/// `x ‖ y`, on the curve, in the prime-order subgroup, not the identity.
fn g1<P: SWCurveConfig>(b: &[u8], w: usize) -> Option<Affine<P>>
where
    P::BaseField: PrimeField,
{
    if b.len() != 2 * w {
        return None;
    }
    let p = Affine::<P>::new_unchecked(coord(&b[..w], w)?, coord(&b[w..], w)?);
    (p.is_on_curve() && p.is_in_correct_subgroup_assuming_on_curve()).then_some(p)
}

/// scaas Schnorr: `R ‖ z`, `e = hashToScalar(keccak256(tag ‖ R ‖ Y ‖ m))` with hashToScalar(s) =
/// `(keccak(s ‖ 0x02) · 2^256 + keccak(s ‖ 0x03)) mod r`; accept iff `z < r`, `R ≠ O`, `e ≠ 0`, `[z]G == R + [e]Y`.
fn schnorr<P: SWCurveConfig>(key_data: &[u8], message: &[u8; 32], sig: &[u8], w: usize) -> bool
where
    P::BaseField: PrimeField,
{
    if sig.len() != 2 * w + 32 {
        return false;
    }
    let (rb, zb) = sig.split_at(2 * w);
    let (Some(r), Some(y), Some(z)) = (g1::<P>(rb, w), g1::<P>(key_data, w), fe::<P::ScalarField>(zb)) else { return false };
    let seed = keccak(&[SCHNORR_TAG, rb, key_data, message]);
    let e = P::ScalarField::from_be_bytes_mod_order(&[keccak(&[&seed, &[2]]), keccak(&[&seed, &[3]])].concat());
    !e.is_zero() && Affine::<P>::generator() * z == r.into_group() + y * e
}

// --- BLS min-sig ---

/// Port of ZetherCurves.sol `G1Bn254.mapToG1`: `x = keccak256(prefix ‖ uint32 ctr) mod p`, the first `x` with
/// `x³ + 3` a square, `y = (x³ + 3)^((p+1)/4)` made even.
pub fn map_to_g1_bn254(prefix: &[u8]) -> ark_bn254::G1Affine {
    use ark_bn254::Fq;
    let mut exp = Fq::MODULUS;
    exp.add_with_carry(&1u64.into());
    exp.div2();
    exp.div2();
    for ctr in 0u32.. {
        let x = Fq::from_be_bytes_mod_order(&keccak(&[prefix, &ctr.to_be_bytes()]));
        let rhs = x * x * x + Fq::from(3u64);
        let y = rhs.pow(exp);
        if y.square() == rhs {
            return ark_bn254::G1Affine::new_unchecked(x, if y.into_bigint().is_odd() { -y } else { y });
        }
    }
    unreachable!("half of all x lift")
}

fn bls_bn254_minsig(key_data: &[u8], message: &[u8; 32], sig: &[u8], pop: bool) -> bool {
    use ark_bn254::{Bn254, Fq, Fq2, G2Affine};
    let Some(s) = g1::<ark_bn254::g1::Config>(sig, 32) else { return false };
    if key_data.len() != 128 {
        return false;
    }
    let w: Vec<Option<Fq>> = (0..4).map(|i| fe(&key_data[32 * i..32 * i + 32])).collect();
    let (Some(xi), Some(xr), Some(yi), Some(yr)) = (w[0], w[1], w[2], w[3]) else { return false };
    let pk = G2Affine::new_unchecked(Fq2::new(xr, xi), Fq2::new(yr, yi)); // EIP-197: imaginary part first
    if !pk.is_on_curve() || !pk.is_in_correct_subgroup_assuming_on_curve() {
        return false;
    }
    let h = map_to_g1_bn254(&[if pop { BN254_LABEL_POP } else { BN254_LABEL_SIG }, message].concat());
    Bn254::pairing(s, G2Affine::generator()) == Bn254::pairing(h, pk)
}

/// RFC 9380 `BLS12381G1_XMD:SHA-256_SSWU_RO_` with the given DST.
pub fn hash_to_g1_bls12381(msg: &[u8], dst: &[u8]) -> ark_bls12_381::G1Affine {
    MapToCurveBasedHasher::<ark_bls12_381::G1Projective, DefaultFieldHasher<Sha256, 128>, WBMap<ark_bls12_381::g1::Config>>::new(dst)
        .and_then(|h| h.hash(msg))
        .expect("RFC 9380 hasher")
}

fn bls12381_minsig(key_data: &[u8], message: &[u8; 32], sig: &[u8], pop: bool) -> bool {
    use ark_bls12_381::{Bls12_381, Fq, Fq2, G2Affine};
    let Some(s) = g1::<ark_bls12_381::g1::Config>(sig, 64) else { return false };
    if key_data.len() != 256 {
        return false;
    }
    let w: Vec<Option<Fq>> = (0..4).map(|i| coord(&key_data[64 * i..64 * i + 64], 64)).collect();
    let (Some(x0), Some(x1), Some(y0), Some(y1)) = (w[0], w[1], w[2], w[3]) else { return false };
    let pk = G2Affine::new_unchecked(Fq2::new(x0, x1), Fq2::new(y0, y1)); // EIP-2537: c0 first
    if !pk.is_on_curve() || !pk.is_in_correct_subgroup_assuming_on_curve() {
        return false;
    }
    let h = hash_to_g1_bls12381(message, if pop { BLS12381_DST_POP } else { BLS12381_DST_SIG });
    Bls12_381::pairing(s, G2Affine::generator()) == Bls12_381::pairing(h, pk)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_unpadded() {
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foo"), "Zm9v");
        assert_eq!(base64url(&[0xfb, 0xff]), "-_8");
    }

    /// RFC 9380 Appendix J.9.1 (BLS12381G1_XMD:SHA-256_SSWU_RO_), msg = "": pins the arkworks hasher to the RFC.
    #[test]
    fn rfc9380_g1_ro_empty_message() {
        let p = hash_to_g1_bls12381(b"", b"QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_");
        let x = p.x().unwrap().into_bigint().to_bytes_be();
        assert_eq!(
            hex(&x),
            "052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1"
        );
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
```

- [ ] **Step 5: Wire it.** In `clients/scaas-ua/src/lib.rs`, after `pub use keydata::validate_key_data;` add one line:

```rust
pub mod verify;
```

In `clients/scaas-ua/Cargo.toml` `[dependencies]`, replace the `k256` and `p256` lines and add `sha2` (exact pin):

```toml
k256 = { version = "0.13", default-features = false, features = ["arithmetic", "ecdsa", "schnorr"] }
p256 = { version = "0.13", default-features = false, features = ["arithmetic", "ecdsa"] }
sha2 = "=0.10.9"
```

`Cargo.lock`: cargo adds exactly `ecdsa 0.16.9`, `hmac 0.12.1`, `rfc6979 0.4.0`, `sha2 0.10.9`, `signature 2.2.0` (all in the
local registry cache, so `--offline` resolves them) and the matching dependency edges of `k256`, `p256`, `elliptic-curve`
and `scaas-ua`; no existing version moves. (The resolved file is `R/vectors/repo/clients/scaas-ua/Cargo.lock` of the spike.)

- [ ] **Step 6: Rust cross-check test.** Create `clients/scaas-ua/tests/signatures.rs`:

```rust
//! scaas-ua `verify` against smartcontracts/vectors/ua/signatures.json (generated by clientkeys scripts/ua-sig-vectors.mjs
//! from noble): every positive verifies, every negative is refused, every msig set gives its verdict.
use scaas_ua::verify::{native_ecdsa, verify};
use scaas_ua::*;
use serde_json::Value;

fn load() -> Value {
    let path = format!("{}/../../smartcontracts/vectors/ua/signatures.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}
fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn b32(v: &Value) -> [u8; 32] {
    bytes(v).try_into().unwrap()
}
fn num(v: &Value) -> u64 {
    v.as_u64().unwrap()
}
fn s(v: &Value) -> &str {
    v.as_str().unwrap()
}
fn arr(v: &Value) -> &Vec<Value> {
    v.as_array().unwrap()
}
fn domain(v: &Value, ctx: &str, generation: u32) -> Domain {
    let c = &v["contexts"][ctx];
    Domain {
        generation,
        chain_id: num(&c["chainId"]),
        registry: bytes(&c["registry"]).try_into().unwrap(),
        chain_uid: b32(&c["chainUid"]),
    }
}

#[test]
fn derived_positives_verify() {
    let v = load();
    assert_eq!(arr(&v["derived"]).len(), 7);
    let mut n = 0;
    for r in arr(&v["derived"]) {
        let (kind, kd) = (num(&r["kind"]) as u16, bytes(&r["keyData"]));
        assert_eq!(derive_ua(kind, &kd, false).unwrap(), b32(&r["ua"]), "{}", r["name"]);
        for p in [&r["pop"], &r["popOther"]] {
            let d = domain(&v, s(&p["context"]), 1);
            let pd = pop_digest(d.chain_id, &d.chain_uid, &d.registry, &b32(&r["ua"]), &[0; 32]);
            assert_eq!(pd, b32(&p["popDigest"]));
            let m = ua_message(kind, &purpose_tag("pop").unwrap(), &pd).unwrap();
            assert_eq!(m, b32(&p["message"]));
            assert!(verify(kind, &kd, &m, &bytes(&p["sig"]), true), "{} pop {}", r["name"], p["context"]);
            n += 1;
        }
        for x in arr(&r["sigs"]) {
            let m = ua_message(kind, &purpose_tag(s(&x["purpose"])).unwrap(), &b32(&x["digest"])).unwrap();
            assert_eq!(m, b32(&x["message"]));
            assert!(verify(kind, &kd, &m, &bytes(&x["sig"]), false), "{} {} {}", r["name"], x["purpose"], x["variant"]);
            n += 1;
        }
    }
    println!("{n} derived positives verified");
}

#[test]
fn derived_negatives_refused() {
    let v = load();
    let mut n = 0;
    for r in arr(&v["derived"]) {
        let (kind, kd) = (num(&r["kind"]) as u16, bytes(&r["keyData"]));
        for x in arr(&r["negatives"]) {
            let pop = x["verifyPop"].as_bool().unwrap();
            assert!(!verify(kind, &kd, &b32(&x["message"]), &bytes(&x["sig"]), pop), "{} {}", r["name"], x["name"]);
            n += 1;
        }
    }
    println!("{n} derived negatives refused");
}

#[test]
fn native_uaauth() {
    let v = load();
    let nat = &v["native"];
    let addr: [u8; 20] = bytes(&nat["address"]).try_into().unwrap();
    let ua = native_id(0x0001, &addr).unwrap();
    assert_eq!(ua, b32(&nat["ua"]));
    for x in arr(&nat["sigs"]) {
        let d = domain(&v, s(&x["context"]), num(&x["generation"]) as u32);
        let h = ua_auth_digest(&d, &ua, &purpose_tag(s(&x["purpose"])).unwrap(), &b32(&x["digest"]));
        assert_eq!(h, b32(&x["uaAuthDigest"]));
        assert!(native_ecdsa(&addr, &h, &bytes(&x["sig"])), "{} {}", x["context"], x["generation"]);
    }
    for x in arr(&nat["negatives"]) {
        let d = domain(&v, s(&x["context"]), num(&x["generation"]) as u32);
        let h = ua_auth_digest(&d, &ua, &purpose_tag(s(&x["purpose"])).unwrap(), &b32(&x["digest"]));
        assert!(!native_ecdsa(&addr, &h, &bytes(&x["sig"])), "{}", x["name"]);
    }
}

// --- msig: the registry path of §1.9, auth = abi.encode(bytes keyData, bytes abi.encode(MemberSig[])) ---

fn word(b: &[u8], o: usize) -> Option<usize> {
    let w = b.get(o..o + 32)?;
    w[..24].iter().all(|x| *x == 0).then(|| w[24..].iter().fold(0usize, |a, x| (a << 8) | *x as usize))
}
fn dyn_bytes(b: &[u8], base: usize, head: usize) -> Option<&[u8]> {
    let o = base + word(b, head)?;
    b.get(o + 32..o + 32 + word(b, o)?)
}
fn u16_at(d: &[u8], o: usize) -> usize {
    ((d[o] as usize) << 8) | d[o + 1] as usize
}

fn msig_ok(v: &Value, ua: &[u8; 32], purpose: &[u8; 32], digest: &[u8; 32], auth: &[u8]) -> Option<bool> {
    let key = dyn_bytes(auth, 0, 0)?;
    let sigs = dyn_bytes(auth, 0, 32)?;
    if ua_of(0x0120, key).ok()? != *ua {
        return Some(false);
    }
    let (threshold, count) = (u16_at(key, 0), u16_at(key, 2));
    let md = member_digest(ua, &ua_message(0x0120, purpose, digest).ok()?);
    let member = purpose_tag("member").ok()?;
    let a = word(sigs, 0)?;
    let base = a + 32;
    let (mut sum, mut last) = (0usize, None);
    for i in 0..word(sigs, a)? {
        if sum >= threshold {
            return Some(false); // a MemberSig after the threshold
        }
        let t = base + word(sigs, base + 32 * i)?;
        let index = word(sigs, t)?;
        if last.is_some_and(|l| index <= l) || index >= count {
            return Some(false);
        }
        last = Some(index);
        let o = 4 + 36 * index;
        let kind = u16_at(key, o) as u16;
        let id: [u8; 32] = key[o + 2..o + 34].try_into().ok()?;
        let (mkd, sig) = (dyn_bytes(sigs, t, t + 32)?, dyn_bytes(sigs, t, t + 64)?);
        let ok = if is_native(kind) {
            let d = domain(v, s(&v["msig"]["context"]), num(&v["msig"]["generation"]) as u32);
            native_ecdsa(&id[12..].try_into().ok()?, &ua_auth_digest(&d, &id, &member, &md), sig)
        } else {
            ua_of(kind, mkd).ok()? == id && verify(kind, mkd, &ua_message(kind, &member, &md).ok()?, sig, false)
        };
        if !ok {
            return Some(false);
        }
        sum += u16_at(key, o + 34);
    }
    Some(sum >= threshold)
}

#[test]
fn msig_sets() {
    let v = load();
    let m = &v["msig"];
    let members: Vec<(u16, [u8; 32], u16)> =
        arr(&m["members"]).iter().map(|x| (num(&x["kind"]) as u16, b32(&x["id"]), num(&x["weight"]) as u16)).collect();
    let key = encode_msig(num(&m["threshold"]) as u16, &members);
    assert_eq!(key, bytes(&m["keyData"]));
    let ua = derive_ua(0x0120, &key, false).unwrap();
    assert_eq!(ua, b32(&m["ua"]));
    for x in arr(&m["sets"]) {
        let p = purpose_tag(s(&x["purpose"])).unwrap();
        let d = b32(&x["digest"]);
        assert_eq!(member_digest(&ua, &ua_message(0x0120, &p, &d).unwrap()), b32(&x["memberDigest"]));
        let got = msig_ok(&v, &ua, &p, &d, &bytes(&x["auth"])).unwrap_or(false);
        assert_eq!(got, x["valid"].as_bool().unwrap(), "{}", x["name"]);
    }
}

#[test]
fn bip340_official_vectors() {
    let v = load();
    assert_eq!(arr(&v["bip340Official"]).len(), 15);
    for t in arr(&v["bip340Official"]) {
        let ok = verify(0x0103, &bytes(&t["publicKey"]), &b32(&t["message"]), &bytes(&t["sig"]), false);
        assert_eq!(ok, t["valid"].as_bool().unwrap(), "vector {}", t["index"]);
    }
}
```

- [ ] **Step 7: Test (node).** `cd clients/clientkeys && ../../scripts/capped node --test test/ua-sig.test.js` — expected:

```
✔ the generator reproduces signatures.json byte for byte (564.322949ms)
✔ derived kinds: key data, ids, PoP messages, every signature verifies (463.655977ms)
✔ derived kinds: every negative fails (377.870481ms)
✔ native EOA: UAAuth signatures verify, negatives fail (11.786883ms)
✔ msig: structure id, members, every set gives its verdict (92.998345ms)
✔ BIP-340 official vectors (32-byte messages) give their verdict (15.993768ms)
ℹ tests 6
ℹ suites 0
ℹ pass 6
ℹ fail 0
ℹ cancelled 0
ℹ skipped 0
ℹ todo 0
ℹ duration_ms 1643.099414
```

- [ ] **Step 8: Test (Rust).** `cd clients/scaas-ua && ../../scripts/capped cargo test --offline` then
  `../../scripts/capped cargo clippy --offline --all-targets` (no warnings) — expected test lines:

```
     Running unittests src/lib.rs (target/debug/deps/scaas_ua-f596c265a208d394)
running 2 tests
test verify::tests::base64url_unpadded ... ok
test verify::tests::rfc9380_g1_ro_empty_message ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
     Running tests/signatures.rs (target/debug/deps/signatures-d534b9b2ed5fef88)
running 5 tests
test bip340_official_vectors ... ok
test native_uaauth ... ok
test msig_sets ... ok
test derived_positives_verify ... ok
test derived_negatives_refused ... ok
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.63s
     Running tests/vectors.rs (target/debug/deps/vectors-4dc726f384a4f16b)
running 6 tests
test structures ... ok
test table_groups_purposes_constants ... ok
test messages ... ok
test natives_native_space_canonical_ids ... ok
test valid_rows ... ok
test invalid_rows ... ok
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
running 0 tests
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

  (`cargo test --test signatures -- --nocapture` additionally prints `30 derived positives verified` and
  `59 derived negatives refused`.)

- [ ] **Step 9: Commit.**

```bash
/usr/bin/git add clients/clientkeys/scripts/ua-sig-vectors.mjs clients/clientkeys/test/ua-sig.test.js \
  smartcontracts/vectors/ua/signatures.json clients/scaas-ua/src/verify.rs clients/scaas-ua/src/lib.rs \
  clients/scaas-ua/tests/signatures.rs clients/scaas-ua/Cargo.toml clients/scaas-ua/Cargo.lock
/usr/bin/git commit -m "UA-2a T1: signature vectors (signatures.json), node re-verification, Rust verify cross-check

Generator scripts/ua-sig-vectors.mjs: per UA-2a kind a deterministic key, PoP in contexts A and B,
metatx/member signatures and negatives; native EOA UAAuth signatures; an msig structure with member
signature sets (auth = abi.encode(bytes keyData, bytes abi.encode(MemberSig[])), spec 1.9); the official
BIP-340 vectors 0-14. Re-verified with noble (test/ua-sig.test.js) and independently in Rust
(scaas-ua verify: p256, k256, arkworks; own bn254 mapToG1 port, arkworks RFC 9380 hasher).

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 2: ECC verifiers: P-256, WebAuthn-P256, BIP-340

**Files:**
- Create: `smartcontracts/evm/src/ua/IUAVerifier.sol`
- Create: `smartcontracts/evm/src/common/WebAuthnClientData.sol`
- Create: `smartcontracts/evm/src/ua/verifiers/P256Precompile.sol`
- Create: `smartcontracts/evm/src/ua/verifiers/P256Verifier.sol`
- Create: `smartcontracts/evm/src/ua/verifiers/WebAuthnP256Verifier.sol`
- Create: `smartcontracts/evm/src/ua/verifiers/Bip340Verifier.sol`
- Create: `smartcontracts/evm/test/ua/verifiers/EccVerifiers.t.sol`
- Modify: `smartcontracts/evm/src/ua/PqUA.sol`
- Modify: `smartcontracts/evm/src/ua/MlDsa.sol`
- Modify: `smartcontracts/evm/src/ua/SlhDsa.sol`
- Modify: `smartcontracts/evm/src/ua/FnDsa.sol`
- Modify: `smartcontracts/evm/src/account/SmartKeyAccount.sol`

**Interfaces:**
- Consumes: `UAKinds` (`uaMessage`, `uaOf`, `popDigest`, `chainKeyHash`, kind ids, purpose tags); OpenZeppelin `P256`
  (`verifySolidity`, `isValidPublicKey`, `N`, `GX`, `GY`) and `Base64.encodeURL`; P256VERIFY at 0x100 (EIP-7951) when the
  constructor probe passes; `smartcontracts/vectors/ua/signatures.json` (the vectors task, must land first); the official
  BIP-340 vectors (bitcoin/bips `bip-0340/test-vectors.csv`, rows 0–14, embedded in the test).
- Produces: `IUAKindVerifier` (moved, unchanged) and `IUAPopVerifier is IUAKindVerifier` (`verifyPop`) in
  `src/ua/IUAVerifier.sol` — the registry and the pairing verifiers import from there; `P256Verifier` (0x0101),
  `WebAuthnP256Verifier` (0x0100), `Bip340Verifier` (0x0103), stateless, `verifyPop == verify`, false (never a revert) on
  malformed input; the two P-256 verifiers expose `bool PRECOMPILE` (immutable, constructor probe of 0x100) — the chain
  profile can read it to pick the P-256 `verifyCap`; `WebAuthnClientData.parse` (the `SmartKeyAccount` clientDataJSON
  grammar, origin returned, not judged), now also used by `SmartKeyAccount._clientDataOk`.

- [ ] **Step 1: Verifier interfaces.** Create `smartcontracts/evm/src/ua/IUAVerifier.sol` (the `IUAKindVerifier` text is moved verbatim from `PqUA.sol`):

```solidity
// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

/// @title Per-kind UA verifier (accounts.md CTR-UA-17 "Verifiers").
/// @notice Stateless. The registry has matched `keyData` against the id (or read the stored key from `keyPtr`);
///         `message` is the 32-byte `ua_msg` (CTR-UA-12). A malformed input returns false, never true.
interface IUAKindVerifier {
    function verify(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool);
}

/// @title Per-kind UA verifier with the proof of possession (accounts.md §1.4, CTR-UA-07).
/// @notice `message` is `uaMessage(kind, PURPOSE_POP, popDigest(...))`. A kind whose PoP needs its own domain (the BLS
///         min-sig kinds: `DST_POP` / the POP label) checks it here; for every other kind `verifyPop == verify`.
///         Malformed input returns false and never reverts.
interface IUAPopVerifier is IUAKindVerifier {
    function verifyPop(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool);
}
```

- [ ] **Step 2: Move `IUAKindVerifier` out of `PqUA.sol`; the PQ verifiers import it from `IUAVerifier.sol`.** These are the `PqUA.sol`, `MlDsa.sol`, `SlhDsa.sol`, `FnDsa.sol` hunks of the diff in Step 4 — apply that diff once, in Step 4, not separately here (they delete the interface from `PqUA.sol` and split the imports: `import {IUAKindVerifier} from "./IUAVerifier.sol";` + `import {PqUA} from "./PqUA.sol";`; `FnDsa.sol` only the first). Nothing else imports `IUAKindVerifier`.

- [ ] **Step 3: Shared clientDataJSON grammar.** Create `smartcontracts/evm/src/common/WebAuthnClientData.sol` (the body of `SmartKeyAccount._clientDataOk` and `_hashSlice`, with the origin comparison lifted out to the caller):

```solidity
// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";

/// @title The strict clientDataJSON grammar shared by `SmartKeyAccount` (CTR-ACC-08) and the UA `webauthn-p256`
///        verifier (accounts.md §1.9).
library WebAuthnClientData {
    /// @dev The bounded WebAuthn L3 §5.8.1.2 check: the fixed prefix with type and challenge, the origin up to the
    ///      next `"`, then exactly one of: `}` as the last character (Safari, L2), or `,"crossOrigin":false` followed
    ///      by `}` or `,` (Chrome, Firefox, L3). Everything else (`crossOrigin:true`, a member before crossOrigin,
    ///      whitespace) fails closed. The origin is returned as `cd[originStart .. originStart + originLen)` and not
    ///      judged here: the account compares its hash, the UA verifier accepts any origin.
    function parse(bytes memory cd, bytes32 challenge)
        internal
        pure
        returns (bool ok, uint256 originStart, uint256 originLen)
    {
        bytes memory prefix = abi.encodePacked(
            '{"type":"webauthn.get","challenge":"', Base64.encodeURL(abi.encodePacked(challenge)), '","origin":"'
        );
        uint256 p = prefix.length;
        uint256 n = cd.length;
        if (n < p + 2 || hashSlice(cd, 0, p) != keccak256(prefix)) return (false, 0, 0);
        uint256 end = p;
        while (end < n && cd[end] != '"') ++end;
        if (end + 1 >= n) return (false, 0, 0);
        (originStart, originLen) = (p, end - p);
        if (cd[end + 1] == "}") return (end + 2 == n, originStart, originLen);
        bytes memory crossFalse = ',"crossOrigin":false';
        uint256 after_ = end + 1 + crossFalse.length;
        if (after_ >= n || hashSlice(cd, end + 1, crossFalse.length) != keccak256(crossFalse)) return (false, 0, 0);
        if (cd[after_] == "}") return (after_ + 1 == n, originStart, originLen);
        return (cd[after_] == ",", originStart, originLen);
    }

    /// @dev `keccak256(b[start .. start + len))`; the caller keeps the range inside `b`.
    function hashSlice(bytes memory b, uint256 start, uint256 len) internal pure returns (bytes32 h) {
        assembly ("memory-safe") {
            h := keccak256(add(add(b, 32), start), len)
        }
    }
}
```

- [ ] **Step 4: `SmartKeyAccount` uses the library** (same accept set: the origin hash is still compared, the order of the checks does not change the result; runtime 18,738 → 18,797 bytes). Whole diff for Steps 2 and 4 (`git apply --check -p1` passes on `main` ee86883):

```diff
--- a/smartcontracts/evm/src/ua/PqUA.sol
+++ b/smartcontracts/evm/src/ua/PqUA.sol
@@ -1,13 +1,6 @@
 // SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
 pragma solidity ^0.8.24;
 
-/// @title Per-kind UA verifier (accounts.md CTR-UA-17 "Verifiers").
-/// @notice Stateless. The registry has matched `keyData` against the id (or read the stored key from `keyPtr`);
-///         `message` is the 32-byte `ua_msg` (CTR-UA-12). A malformed input returns false, never true.
-interface IUAKindVerifier {
-    function verify(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool);
-}
-
 /// @title PQ signing kinds: tags, the PQ message and the precompile probe (accounts.md CTR-UA-23).
 /// @notice ML-DSA and SLH-DSA sign `pq_msg = keccak256(TAG(kind) ‖ ua_msg)` with the empty FIPS 204 / FIPS 205
 ///         context, so the signed message is `M' = 0x00 ‖ 0x00 ‖ pq_msg`; FN-DSA (Falcon) signs `ua_msg` itself,
--- a/smartcontracts/evm/src/ua/MlDsa.sol
+++ b/smartcontracts/evm/src/ua/MlDsa.sol
@@ -1,7 +1,8 @@
 // SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
 pragma solidity ^0.8.24;
 
-import {IUAKindVerifier, PqUA} from "./PqUA.sol";
+import {IUAKindVerifier} from "./IUAVerifier.sol";
+import {PqUA} from "./PqUA.sol";
 import {Shake} from "./Shake.sol";
 import {PqNtt} from "./PqNtt.sol";
 
--- a/smartcontracts/evm/src/ua/SlhDsa.sol
+++ b/smartcontracts/evm/src/ua/SlhDsa.sol
@@ -1,7 +1,8 @@
 // SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
 pragma solidity ^0.8.24;
 
-import {IUAKindVerifier, PqUA} from "./PqUA.sol";
+import {IUAKindVerifier} from "./IUAVerifier.sol";
+import {PqUA} from "./PqUA.sol";
 
 /// @title SLH-DSA-SHA2-128s verification (FIPS 205, Algorithms 8, 11, 13, 17, 20; SHA2 category 1, §11.2.1).
 /// @notice n = 16, h = 63, d = 7, h' = 9, a = 12, k = 14, lg w = 4, len = 35, m = 30; pk = PK.seed ‖ PK.root (32 B),
--- a/smartcontracts/evm/src/ua/FnDsa.sol
+++ b/smartcontracts/evm/src/ua/FnDsa.sol
@@ -1,7 +1,7 @@
 // SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
 pragma solidity ^0.8.24;
 
-import {IUAKindVerifier} from "./PqUA.sol";
+import {IUAKindVerifier} from "./IUAVerifier.sol";
 import {Shake} from "./Shake.sol";
 import {PqNtt} from "./PqNtt.sol";
 
--- a/smartcontracts/evm/src/account/SmartKeyAccount.sol
+++ b/smartcontracts/evm/src/account/SmartKeyAccount.sol
@@ -4,11 +4,11 @@
 import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
 import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";
 import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
-import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
 import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
 import {MetaTxBase} from "../metatx/MetaTxBase.sol";
 import {IMetaTx} from "../metatx/IMetaTx.sol";
 import {MetaTxLib} from "../common/MetaTxLib.sol";
+import {WebAuthnClientData} from "../common/WebAuthnClientData.sol";
 
 enum KeyKind {
     NONE,           // 0: empty or removed slot
@@ -312,28 +312,9 @@
         return P256.verify(h, r, s, k.x, k.y);
     }
 
-    /// @dev The bounded WebAuthn L3 §5.8.1.2 check: the fixed prefix with type and challenge, the origin up to the
-    ///      next `"`, then exactly one of: `}` as the last character (Safari, L2), or `,"crossOrigin":false` followed
-    ///      by `}` or `,` (Chrome, Firefox, L3). Everything else (`crossOrigin:true`, a member before crossOrigin,
-    ///      whitespace) fails closed.
+    /// @dev The strict clientDataJSON grammar (`WebAuthnClientData.parse`) with the key's origin.
     function _clientDataOk(bytes memory cd, bytes32 challenge, bytes32 originHash) private pure returns (bool) {
-        bytes memory prefix = abi.encodePacked(
-            '{"type":"webauthn.get","challenge":"', Base64.encodeURL(abi.encodePacked(challenge)), '","origin":"');
-        uint256 p = prefix.length;
-        uint256 n = cd.length;
-        if (n < p + 2 || _hashSlice(cd, 0, p) != keccak256(prefix)) return false;
-        uint256 end = p;
-        while (end < n && cd[end] != '"') ++end;
-        if (end + 1 >= n || _hashSlice(cd, p, end - p) != originHash) return false;
-        if (cd[end + 1] == "}") return end + 2 == n;
-        bytes memory crossFalse = ',"crossOrigin":false';
-        uint256 after_ = end + 1 + crossFalse.length;
-        if (after_ >= n || _hashSlice(cd, end + 1, crossFalse.length) != keccak256(crossFalse)) return false;
-        if (cd[after_] == "}") return after_ + 1 == n;
-        return cd[after_] == ",";
-    }
-
-    function _hashSlice(bytes memory b, uint256 start, uint256 len) private pure returns (bytes32 h) {
-        assembly ("memory-safe") { h := keccak256(add(add(b, 32), start), len) }
+        (bool ok, uint256 o, uint256 len) = WebAuthnClientData.parse(cd, challenge);
+        return ok && WebAuthnClientData.hashSlice(cd, o, len) == originHash;
     }
 }
```

- [ ] **Step 5: Probed P256VERIFY.** Create `smartcontracts/evm/src/ua/verifiers/P256Precompile.sol` (constructor probe: the fixed vector must give exactly the word 1 and the same vector with `h` flipped must not; then low-s / range / on-curve checks and one precompile call; else `P256.verifySolidity`). OZ `P256.verify` is not used: it reads the precompile's empty "invalid" answer as "absent" and runs the Solidity verifier (~250 k) for every invalid signature:

```solidity
// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";

/// @title Low-s ECDSA-P256 through P256VERIFY (0x100, EIP-7951) when the constructor's probe proves it, else the
///        OpenZeppelin Solidity verifier.
/// @notice The probe asks 0x100 one fixed valid vector (key = G, `h = sha256("scaas.ua.p256.probe")`) and the same
///         vector with `h` flipped: present iff exactly the 32-byte word 1, then anything but 1. An empty account, a
///         contract answering 1 to everything or another precompile fails the probe and the verifier stays on the
///         Solidity path. With the precompile an invalid signature costs one precompile call, not the Solidity
///         verifier (OZ `P256.verify` reads the precompile's empty "invalid" answer as "absent" and falls back).
abstract contract P256Precompile {
    uint256 private constant _HALF_N = P256.N / 2;
    /// sha256("scaas.ua.p256.probe") and its low-s signature under the private key 1 (forge `vm.signP256`).
    bytes32 internal constant PROBE_H = 0x8708b9c1b15ea4b9eceaf938fc2b0ac2f8643b92d02c9c9d202a540a97c0f1e9;
    bytes32 internal constant PROBE_R = 0xb73892af0c08dbba796b57346b43b924c690fa3c5e70a70904ce3285b2f4ca89;
    bytes32 internal constant PROBE_S = 0x6da50c09d4911f559acd8c1bfbdb1e82b16a9ed0f53ed7f9ed3e56e1d793bef1;

    /// True iff this chain's 0x100 passed the constructor probe.
    bool public immutable PRECOMPILE;

    constructor() {
        bytes32 gx = bytes32(P256.GX);
        bytes32 gy = bytes32(P256.GY);
        PRECOMPILE =
            _call(PROBE_H, PROBE_R, PROBE_S, gx, gy) && !_call(PROBE_H ^ bytes32(uint256(1)), PROBE_R, PROBE_S, gx, gy);
    }

    function _p256Verify(bytes32 h, bytes32 r, bytes32 s, bytes32 x, bytes32 y) internal view returns (bool) {
        if (!PRECOMPILE) return P256.verifySolidity(h, r, s, x, y);
        if (uint256(r) == 0 || uint256(r) >= P256.N || uint256(s) == 0 || uint256(s) > _HALF_N) return false;
        if (!P256.isValidPublicKey(x, y)) return false;
        return _call(h, r, s, x, y);
    }

    /// One P256VERIFY call: true only on success with exactly 32 bytes equal to 1.
    function _call(bytes32 h, bytes32 r, bytes32 s, bytes32 x, bytes32 y) private view returns (bool ok) {
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, h)
            mstore(add(m, 0x20), r)
            mstore(add(m, 0x40), s)
            mstore(add(m, 0x60), x)
            mstore(add(m, 0x80), y)
            mstore(0, 0)
            let success := staticcall(gas(), 0x100, m, 0xa0, 0, 0x20)
            ok := and(and(success, eq(returndatasize(), 0x20)), eq(mload(0), 1))
        }
    }
}
```

- [ ] **Step 6: `P256Verifier`.** Create `smartcontracts/evm/src/ua/verifiers/P256Verifier.sol`:

```solidity
// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {IUAPopVerifier} from "../IUAVerifier.sol";
import {P256Precompile} from "./P256Precompile.sol";

/// @title UA verifier for `p256` (0x0101, accounts.md §1.9).
/// @notice keyData = `x ‖ y` (64), sig = `r ‖ s` (64), low-s ECDSA-P256 over `sha256(ua_msg)`
///         (`P256Precompile`: P256VERIFY when probed, else the OpenZeppelin Solidity verifier).
contract P256Verifier is IUAPopVerifier, P256Precompile {
    function verify(bytes calldata keyData, bytes32 message, bytes calldata sig) public view returns (bool) {
        if (keyData.length != 64 || sig.length != 64) return false;
        return _p256Verify(
            sha256(abi.encodePacked(message)),
            bytes32(sig[0:32]),
            bytes32(sig[32:64]),
            bytes32(keyData[0:32]),
            bytes32(keyData[32:64])
        );
    }

    function verifyPop(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool) {
        return verify(keyData, message, sig);
    }
}
```

- [ ] **Step 7: `WebAuthnP256Verifier`.** Create `smartcontracts/evm/src/ua/verifiers/WebAuthnP256Verifier.sol`:

```solidity
// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {WebAuthnClientData} from "../../common/WebAuthnClientData.sol";
import {IUAPopVerifier} from "../IUAVerifier.sol";
import {P256Precompile} from "./P256Precompile.sol";

/// @title UA verifier for `webauthn-p256` (0x0100, accounts.md §1.9).
/// @notice keyData = `x ‖ y ‖ rpIdHash` (96); sig = `abi.encode(bytes authenticatorData, string clientDataJSON,
///         uint256 r, uint256 s)` (the `SmartKeyAccount` encoding). Checks: authenticatorData[0:32] == rpIdHash, flags
///         UP and UV, the strict clientDataJSON grammar with challenge = base64url(`ua_msg`) and any origin, then low-s
///         P-256 over `sha256(authenticatorData ‖ sha256(clientDataJSON))` (`P256Precompile`). The
///         ABI blob is decoded by hand with bounds checks: a malformed blob returns false, never reverts.
contract WebAuthnP256Verifier is IUAPopVerifier, P256Precompile {
    uint8 private constant _FLAG_UP = 0x01;
    uint8 private constant _FLAG_UV = 0x04;

    function verify(bytes calldata keyData, bytes32 message, bytes calldata sig) public view returns (bool) {
        if (keyData.length != 96 || sig.length < 128) return false;
        (bool ok, bytes32 h) = _signedHash(bytes32(keyData[64:96]), message, sig);
        if (!ok) return false;
        return
            _p256Verify(h, bytes32(sig[64:96]), bytes32(sig[96:128]), bytes32(keyData[0:32]), bytes32(keyData[32:64]));
    }

    function verifyPop(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool) {
        return verify(keyData, message, sig);
    }

    /// Checks authenticatorData and clientDataJSON; returns `sha256(authenticatorData ‖ sha256(clientDataJSON))`.
    function _signedHash(bytes32 rpIdHash, bytes32 message, bytes calldata sig) private pure returns (bool, bytes32) {
        (bool okA, bytes calldata authData) = _bytesAt(sig, 0);
        (bool okC, bytes calldata clientData) = _bytesAt(sig, 32);
        if (!okA || !okC || authData.length < 37 || bytes32(authData[0:32]) != rpIdHash) return (false, 0);
        if (uint8(authData[32]) & (_FLAG_UP | _FLAG_UV) != (_FLAG_UP | _FLAG_UV)) return (false, 0);
        (bool okJ,,) = WebAuthnClientData.parse(clientData, message);
        if (!okJ) return (false, 0);
        return (true, sha256(abi.encodePacked(authData, sha256(clientData))));
    }

    /// The dynamic `bytes` whose ABI offset is the head word at `head`; false when offset or length leave `b`.
    function _bytesAt(bytes calldata b, uint256 head) private pure returns (bool, bytes calldata) {
        uint256 off = uint256(bytes32(b[head:head + 32]));
        if (off > b.length || b.length - off < 32) return (false, b[0:0]);
        uint256 len = uint256(bytes32(b[off:off + 32]));
        if (len > b.length - off - 32) return (false, b[0:0]);
        return (true, b[off + 32:off + 32 + len]);
    }
}
```

- [ ] **Step 8: `Bip340Verifier`.** Create `smartcontracts/evm/src/ua/verifiers/Bip340Verifier.sol`:

```solidity
// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {IUAPopVerifier} from "../IUAVerifier.sol";

/// @title UA verifier for `bip340` (0x0103, accounts.md §1.9).
/// @notice keyData = x-only `P` (32), sig = `r ‖ s` (64), BIP-340 verify of the 32-byte `ua_msg`:
///         `e = int(sha256(T ‖ T ‖ r ‖ P ‖ m)) mod n` with `T = sha256("BIP0340/challenge")`, accept iff
///         `R = s·G − e·P` is not infinity, has even y and `x(R) == r`. EVM: `ecrecover(−s·P_x, 27, P_x, −e·P_x)`
///         returns `address(P_x⁻¹·(−e·P_x·P + s·P_x·G)) = address(R)` (v = 27 selects P's even-y lift); the expected
///         `R` is `r` lifted to even y with one MODEXP (`p ≡ 3 mod 4`). Off-curve `P` or `r`, `P ≥ p`, `r ≥ p`, `s ≥ n`
///         and wrong lengths return false. Not covered (probability ~2⁻¹²⁸ each, fail closed): `P_x ≥ n`
///         (ecrecover refuses r ≥ n) and `e == 0`.
contract Bip340Verifier is IUAPopVerifier {
    uint256 private constant _P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 private constant _N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    /// sha256("BIP0340/challenge"), pinned by the tests.
    bytes32 internal constant CHALLENGE_TAG = 0x7bb52d7a9fef58323eb1bf7a407db382d2f3f2d81bb1224f49fe518f6d48d37c;

    function verify(bytes calldata keyData, bytes32 message, bytes calldata sig) public view returns (bool) {
        if (keyData.length != 32 || sig.length != 64) return false;
        uint256 px = uint256(bytes32(keyData));
        uint256 rx = uint256(bytes32(sig[0:32]));
        uint256 s = uint256(bytes32(sig[32:64]));
        if (px >= _P || rx >= _P || s >= _N) return false;
        uint256 e = uint256(sha256(abi.encodePacked(CHALLENGE_TAG, CHALLENGE_TAG, rx, px, message))) % _N;
        address got = ecrecover(bytes32(mulmod(_N - s, px, _N)), 27, bytes32(px), bytes32(mulmod(_N - e, px, _N)));
        if (got == address(0)) return false;
        uint256 rhs = addmod(mulmod(mulmod(rx, rx, _P), rx, _P), 7, _P);
        (bool ok, uint256 ry) = _sqrtCandidate(rhs);
        if (!ok || mulmod(ry, ry, _P) != rhs) return false;
        if (ry & 1 == 1) ry = _P - ry;
        return got == address(uint160(uint256(keccak256(abi.encodePacked(rx, ry)))));
    }

    function verifyPop(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool) {
        return verify(keyData, message, sig);
    }

    /// `a^((p+1)/4) mod p` via MODEXP (0x05); false if the call fails (out of gas), never reverts.
    function _sqrtCandidate(uint256 a) private view returns (bool ok, uint256 r) {
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, 32)
            mstore(add(m, 0x20), 32)
            mstore(add(m, 0x40), 32)
            mstore(add(m, 0x60), a)
            mstore(add(m, 0x80), 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c) // (p + 1) / 4
            mstore(add(m, 0xa0), _P)
            ok := and(staticcall(gas(), 0x05, m, 0xc0, m, 0x20), eq(returndatasize(), 0x20))
            r := mload(m)
        }
    }
}
```

- [ ] **Step 9: Tests.** Create `smartcontracts/evm/test/ua/verifiers/EccVerifiers.t.sol` (16 tests: `signatures.json` positives/negatives incl. the PoP digests recomputed from `contexts`; fuzzed own fixtures — `vm.signP256`, a BIP-340 signer on `vm.createWallet`; the 15 official BIP-340 rows with 32-byte messages; malformed key data / sig lengths / off-curve / out-of-range / broken ABI blobs → false; the probe (vector pinned, `PRECOMPILE` == 0x100 answers), probe failing with `vm.mockCall(0x100)` before the deploy — empty answer and a liar answering 1 — both on the Solidity path; invalid P-256 cheap with the precompile; gas against the §1.15 caps):

```solidity
// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {Test, Vm, console} from "forge-std/Test.sol";
import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";
import {UAKinds} from "../../../src/ua/UAKinds.sol";
import {IUAPopVerifier} from "../../../src/ua/IUAVerifier.sol";
import {P256Verifier} from "../../../src/ua/verifiers/P256Verifier.sol";
import {WebAuthnP256Verifier} from "../../../src/ua/verifiers/WebAuthnP256Verifier.sol";
import {Bip340Verifier} from "../../../src/ua/verifiers/Bip340Verifier.sol";

/// UA-2a ECC verifiers (accounts.md §1.9): `p256`, `webauthn-p256`, `bip340`. Positives and negatives from
/// `vectors/ua/signatures.json`, own fixtures (vm.signP256, a BIP-340 signer on vm.createWallet), the official
/// BIP-340 vectors with 32-byte messages, malformed inputs (false, never a revert), the Solidity path (P256VERIFY
/// probe failed) and gas against the §1.15 caps.
contract EccVerifiersTest is Test {
    uint256 internal constant N_P256 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    uint256 internal constant N_K1 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    uint256 internal constant P_K1 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    bytes32 internal constant RP_ID_HASH = keccak256("rp.example"); // any 32 bytes
    string internal constant ORIGIN = "https://wallet.example";
    // §1.15 starting caps.
    uint256 internal constant CAP_P256 = 400_000;
    uint256 internal constant CAP_WEBAUTHN = 400_000;
    uint256 internal constant CAP_BIP340 = 50_000;

    P256Verifier internal p256;
    WebAuthnP256Verifier internal webauthn;
    Bip340Verifier internal bip340;

    function setUp() public {
        p256 = new P256Verifier();
        webauthn = new WebAuthnP256Verifier();
        bip340 = new Bip340Verifier();
    }

    // ------------------------------------------------------------------ helpers

    function _msg(uint16 kind, bytes32 digest) internal pure returns (bytes32) {
        return UAKinds.uaMessage(kind, UAKinds.PURPOSE_METATX, digest);
    }

    function _p256Key(uint256 pk) internal pure returns (bytes memory) {
        (uint256 x, uint256 y) = vm.publicKeyP256(pk);
        return abi.encodePacked(x, y);
    }

    /// Low-s ECDSA-P256 over `h`.
    function _p256Sign(uint256 pk, bytes32 h) internal pure returns (bytes32 r, bytes32 s) {
        (r, s) = vm.signP256(pk, h);
        if (uint256(s) > N_P256 / 2) s = bytes32(N_P256 - uint256(s));
    }

    function _p256Sig(uint256 pk, bytes32 message) internal pure returns (bytes memory) {
        (bytes32 r, bytes32 s) = _p256Sign(pk, sha256(abi.encodePacked(message)));
        return abi.encodePacked(r, s);
    }

    function _authData(bytes32 rpIdHash, uint8 flags) internal pure returns (bytes memory) {
        return abi.encodePacked(rpIdHash, flags, uint32(7));
    }

    function _clientData(bytes32 challenge, string memory tail) internal pure returns (bytes memory) {
        return abi.encodePacked(
            '{"type":"webauthn.get","challenge":"',
            Base64.encodeURL(abi.encodePacked(challenge)),
            '","origin":"',
            ORIGIN,
            '"',
            tail
        );
    }

    function _waSig(uint256 pk, bytes memory authData, bytes memory clientData) internal pure returns (bytes memory) {
        (bytes32 r, bytes32 s) = _p256Sign(pk, sha256(abi.encodePacked(authData, sha256(clientData))));
        return abi.encode(authData, string(clientData), uint256(r), uint256(s));
    }

    function _waKey(uint256 pk) internal pure returns (bytes memory) {
        return abi.encodePacked(_p256Key(pk), RP_ID_HASH);
    }

    /// BIP-340 signing on vm.createWallet: returns the x-only key and `r ‖ s` over `m` with nonce `k`.
    function _bipSign(uint256 d, uint256 k, bytes32 m) internal returns (bytes memory key, bytes memory sig) {
        Vm.Wallet memory w = vm.createWallet(d);
        if (w.publicKeyY & 1 == 1) d = N_K1 - d;
        Vm.Wallet memory wr = vm.createWallet(k);
        if (wr.publicKeyY & 1 == 1) k = N_K1 - k;
        bytes32 t = sha256("BIP0340/challenge");
        uint256 e = uint256(sha256(abi.encodePacked(t, t, wr.publicKeyX, w.publicKeyX, m))) % N_K1;
        key = abi.encodePacked(w.publicKeyX);
        sig = abi.encodePacked(wr.publicKeyX, addmod(k, mulmod(e, d, N_K1), N_K1));
    }

    function _flip(bytes memory b, uint256 i) internal pure returns (bytes memory c) {
        c = bytes.concat(b);
        c[i] = c[i] ^ 0x01;
    }

    function _both(IUAPopVerifier v, bytes memory key, bytes32 m, bytes memory sig) internal view returns (bool) {
        bool a = v.verify(key, m, sig);
        assertEq(a, v.verifyPop(key, m, sig), "verifyPop == verify");
        return a;
    }

    function _gas(IUAPopVerifier v, bool pop, bytes memory key, bytes32 m, bytes memory sig)
        internal
        view
        returns (uint256 used, bool ok)
    {
        uint256 g = gasleft();
        ok = pop ? v.verifyPop(key, m, sig) : v.verify(key, m, sig);
        used = g - gasleft();
    }

    // ------------------------------------------------------------------ vectors/ua/signatures.json

    function _verifierFor(string memory name) internal view returns (IUAPopVerifier) {
        bytes32 h = keccak256(bytes(name));
        if (h == keccak256("p256")) return p256;
        if (h == keccak256("webauthn-p256")) return webauthn;
        if (h == keccak256("bip340")) return bip340;
        return IUAPopVerifier(address(0));
    }

    function test_SignatureVectors() public view {
        string memory j = vm.readFile(string.concat(vm.projectRoot(), "/../vectors/ua/signatures.json"));
        uint256 seen;
        for (uint256 i; vm.keyExistsJson(j, string.concat(".derived[", vm.toString(i), "]")); ++i) {
            string memory e = string.concat(".derived[", vm.toString(i), "]");
            IUAPopVerifier v = _verifierFor(vm.parseJsonString(j, string.concat(e, ".name")));
            if (address(v) == address(0)) continue;
            ++seen;
            _vectorEntry(j, e, v);
        }
        assertEq(seen, 3, "p256, webauthn-p256, bip340");
    }

    function _vectorEntry(string memory j, string memory e, IUAPopVerifier v) internal view {
        uint16 kind = uint16(vm.parseJsonUint(j, string.concat(e, ".kind")));
        bytes memory key = vm.parseJsonBytes(j, string.concat(e, ".keyData"));
        bytes32 ua = vm.parseJsonBytes32(j, string.concat(e, ".ua"));
        assertEq(ua, UAKinds.uaOf(kind, key), "ua");
        _pop(j, string.concat(e, ".pop"), v, kind, key, ua);
        _pop(j, string.concat(e, ".popOther"), v, kind, key, ua);
        for (uint256 k; vm.keyExistsJson(j, string.concat(e, ".sigs[", vm.toString(k), "]")); ++k) {
            string memory s = string.concat(e, ".sigs[", vm.toString(k), "]");
            bytes32 m = vm.parseJsonBytes32(j, string.concat(s, ".message"));
            assertEq(
                m,
                UAKinds.uaMessage(
                    kind,
                    vm.parseJsonBytes32(j, string.concat(s, ".purposeTag")),
                    vm.parseJsonBytes32(j, string.concat(s, ".digest"))
                ),
                s
            );
            assertTrue(v.verify(key, m, vm.parseJsonBytes(j, string.concat(s, ".sig"))), s);
        }
        for (uint256 k; vm.keyExistsJson(j, string.concat(e, ".negatives[", vm.toString(k), "]")); ++k) {
            string memory n = string.concat(e, ".negatives[", vm.toString(k), "]");
            bytes32 m = vm.parseJsonBytes32(j, string.concat(n, ".message"));
            bytes memory sig = vm.parseJsonBytes(j, string.concat(n, ".sig"));
            bool ok =
                vm.parseJsonBool(j, string.concat(n, ".verifyPop")) ? v.verifyPop(key, m, sig) : v.verify(key, m, sig);
            assertFalse(ok, vm.parseJsonString(j, string.concat(n, ".name")));
        }
    }

    function _pop(string memory j, string memory p, IUAPopVerifier v, uint16 kind, bytes memory key, bytes32 ua)
        internal
        view
    {
        string memory c = string.concat(".contexts.", vm.parseJsonString(j, string.concat(p, ".context")));
        bytes32 popDigest = UAKinds.popDigest(
            UAKinds.chainKeyHash(vm.parseJsonUint(j, string.concat(c, ".chainId"))),
            vm.parseJsonBytes32(j, string.concat(c, ".chainUid")),
            vm.parseJsonAddress(j, string.concat(c, ".registry")),
            ua,
            bytes32(0)
        );
        assertEq(popDigest, vm.parseJsonBytes32(j, string.concat(p, ".popDigest")), p);
        bytes32 m = vm.parseJsonBytes32(j, string.concat(p, ".message"));
        assertEq(m, UAKinds.uaMessage(kind, UAKinds.PURPOSE_POP, popDigest), p);
        assertTrue(v.verifyPop(key, m, vm.parseJsonBytes(j, string.concat(p, ".sig"))), p);
    }

    // ------------------------------------------------------------------ p256

    function testFuzz_P256Valid(uint256 pk, bytes32 digest) public view {
        pk = bound(pk, 1, N_P256 - 1);
        bytes32 m = _msg(UAKinds.P256, digest);
        assertTrue(_both(p256, _p256Key(pk), m, _p256Sig(pk, m)));
    }

    function test_P256Negatives() public view {
        uint256 pk = 0xA11CE;
        bytes memory key = _p256Key(pk);
        bytes32 m = _msg(UAKinds.P256, keccak256("d"));
        bytes memory sig = _p256Sig(pk, m);
        assertTrue(_both(p256, key, m, sig));
        (bytes32 r, bytes32 s) = abi.decode(sig, (bytes32, bytes32));
        assertFalse(_both(p256, key, m, abi.encodePacked(r, N_P256 - uint256(s))), "high-s");
        assertFalse(_both(p256, key, m, _flip(sig, 5)), "mutated r");
        assertFalse(_both(p256, key, m, _flip(sig, 40)), "mutated s");
        assertFalse(_both(p256, key, UAKinds.uaMessage(UAKinds.P256, UAKinds.PURPOSE_MEMBER, keccak256("d")), sig));
        assertFalse(
            _both(p256, key, UAKinds.uaMessage(UAKinds.WEBAUTHN_P256, UAKinds.PURPOSE_METATX, keccak256("d")), sig)
        );
        assertFalse(_both(p256, _p256Key(pk + 1), m, sig), "other key");
        assertFalse(_both(p256, _flip(key, 63), m, sig), "off-curve key");
        assertFalse(_both(p256, abi.encodePacked(key, bytes1(0)), m, sig), "key 65");
        assertFalse(_both(p256, _slice(key, 63), m, sig), "key 63");
        assertFalse(_both(p256, key, m, abi.encodePacked(sig, bytes1(0))), "sig 65");
        assertFalse(_both(p256, key, m, _slice(sig, 63)), "sig 63");
        assertFalse(_both(p256, key, m, ""), "sig empty");
        assertFalse(_both(p256, key, m, abi.encodePacked(uint256(0), s)), "r = 0");
        assertFalse(_both(p256, key, m, abi.encodePacked(r, uint256(0))), "s = 0");
        assertFalse(_both(p256, key, m, abi.encodePacked(N_P256, s)), "r = n");
        assertFalse(_both(p256, new bytes(64), m, sig), "zero key");
        assertFalse(_both(p256, abi.encodePacked(type(uint256).max, type(uint256).max), m, sig), "key >= p");
    }

    function _slice(bytes memory b, uint256 n) internal pure returns (bytes memory c) {
        c = new bytes(n);
        for (uint256 i; i < n; ++i) {
            c[i] = b[i];
        }
    }

    /// The probe vector of `P256Precompile` (key = G) is valid by the OZ Solidity verifier; `PRECOMPILE` iff 0x100
    /// accepts it.
    function test_P256Probe() public view {
        bytes32 h = sha256("scaas.ua.p256.probe");
        bytes32 r = 0xb73892af0c08dbba796b57346b43b924c690fa3c5e70a70904ce3285b2f4ca89;
        bytes32 s = 0x6da50c09d4911f559acd8c1bfbdb1e82b16a9ed0f53ed7f9ed3e56e1d793bef1;
        assertEq(h, 0x8708b9c1b15ea4b9eceaf938fc2b0ac2f8643b92d02c9c9d202a540a97c0f1e9);
        assertTrue(P256.verifySolidity(h, r, s, bytes32(P256.GX), bytes32(P256.GY)));
        (bool ok, bytes memory out) = address(0x100).staticcall(abi.encode(h, r, s, P256.GX, P256.GY));
        bool present = ok && out.length == 32 && abi.decode(out, (uint256)) == 1;
        assertEq(p256.PRECOMPILE(), present);
        assertEq(webauthn.PRECOMPILE(), present);
    }

    /// Probe fails ⇒ the Solidity path. `vm.mockCall` before the deploy makes 0x100 answer as an empty account
    /// (success, no returndata) or as a liar (1 to everything); forge 1.3.5 has no `vm.setEvmVersion`, and
    /// `FOUNDRY_EVM_VERSION=prague` runs the whole suite without any 0x100.
    function test_P256ProbeFailsSolidityPath() public {
        _solidityPath(bytes(""), "empty 0x100");
    }

    function test_P256ProbeRejectsLiar() public {
        _solidityPath(abi.encode(uint256(1)), "0x100 answers 1");
    }

    function _solidityPath(bytes memory answer, string memory label) internal {
        vm.mockCall(address(0x100), bytes(""), answer);
        P256Verifier v = new P256Verifier();
        WebAuthnP256Verifier w = new WebAuthnP256Verifier();
        assertFalse(v.PRECOMPILE(), label);
        assertFalse(w.PRECOMPILE(), label);
        console.log(label);
        _solidityP256(v, label);
        _solidityWebAuthn(w, label);
    }

    function _solidityP256(P256Verifier v, string memory label) internal view {
        uint256 pk = 0xB0B;
        bytes32 m = _msg(UAKinds.P256, keccak256("fallback"));
        bytes memory key = _p256Key(pk);
        bytes memory sig = _p256Sig(pk, m);
        assertTrue(_both(v, key, m, sig), label);
        assertFalse(_both(v, key, m, _flip(sig, 40)), label);
        (uint256 gv,) = _gas(v, false, key, m, sig);
        (uint256 gw,) = _gas(v, false, key, m, _flip(sig, 40));
        console.log("  p256 Solidity path verify (valid / invalid):", gv, gw);
        assertLt(gv, CAP_P256);
        assertLt(gw, CAP_P256);
    }

    function _solidityWebAuthn(WebAuthnP256Verifier w, string memory label) internal view {
        uint256 pk = 0xB0B;
        bytes32 m = _msg(UAKinds.WEBAUTHN_P256, keccak256("fallback"));
        bytes memory wsig = _waSig(pk, _authData(RP_ID_HASH, 0x05), _clientData(m, "}"));
        (bytes memory ad, string memory c, uint256 r, uint256 s) = abi.decode(wsig, (bytes, string, uint256, uint256));
        bytes memory bad = abi.encode(ad, c, r ^ 1, s);
        assertTrue(_both(w, _waKey(pk), m, wsig), label);
        assertFalse(_both(w, _waKey(pk), m, bad), label);
        (uint256 gv,) = _gas(w, false, _waKey(pk), m, wsig);
        (uint256 gw,) = _gas(w, false, _waKey(pk), m, bad);
        console.log("  webauthn Solidity path verify (valid / invalid):", gv, gw);
        assertLt(gv, CAP_WEBAUTHN);
        assertLt(gw, CAP_WEBAUTHN);
    }

    function _word(bytes memory b, uint256 o) internal pure returns (uint256 w) {
        assembly ("memory-safe") {
            w := mload(add(add(b, 32), o))
        }
    }

    // ------------------------------------------------------------------ webauthn-p256

    function testFuzz_WebAuthnValid(uint256 pk, bytes32 digest) public view {
        pk = bound(pk, 1, N_P256 - 1);
        bytes32 m = _msg(UAKinds.WEBAUTHN_P256, digest);
        bytes memory a = _authData(RP_ID_HASH, 0x05);
        assertTrue(_both(webauthn, _waKey(pk), m, _waSig(pk, a, _clientData(m, "}"))), "safari");
        assertTrue(_both(webauthn, _waKey(pk), m, _waSig(pk, a, _clientData(m, ',"crossOrigin":false}'))), "chrome");
    }

    function test_WebAuthnGrammar() public view {
        uint256 pk = 0xC0FFEE;
        bytes memory key = _waKey(pk);
        bytes32 m = _msg(UAKinds.WEBAUTHN_P256, keccak256("d"));
        bytes memory a = _authData(RP_ID_HASH, 0x05);
        bytes memory l3 = _clientData(m, ',"crossOrigin":false,"other":1}');
        assertTrue(_both(webauthn, key, m, _waSig(pk, a, l3)), "L3 tail");
        bytes memory flags = _authData(RP_ID_HASH, 0x1d);
        assertTrue(_both(webauthn, key, m, _waSig(pk, flags, _clientData(m, "}"))), "UP|UV|BE|BS");
        assertTrue(
            _both(webauthn, key, m, _waSig(pk, abi.encodePacked(a, hex"a1b2c3"), _clientData(m, "}"))), "authData > 37"
        );
        bytes memory other = abi.encodePacked(
            '{"type":"webauthn.get","challenge":"', Base64.encodeURL(abi.encodePacked(m)), '","origin":""}'
        );
        assertTrue(_both(webauthn, key, m, _waSig(pk, a, other)), "any origin, even empty");

        assertFalse(_both(webauthn, key, m, _waSig(pk, a, _clientData(m, ',"crossOrigin":true}'))), "crossOrigin true");
        assertFalse(_both(webauthn, key, m, _waSig(pk, a, _clientData(m, ', "crossOrigin":false}'))), "whitespace");
        assertFalse(_both(webauthn, key, m, _waSig(pk, a, _clientData(m, ',"x":1}'))), "member before crossOrigin");
        assertFalse(_both(webauthn, key, m, _waSig(pk, a, _clientData(m, "} "))), "trailing");
        assertFalse(_both(webauthn, key, m, _waSig(pk, a, _clientData(m, ""))), "unterminated");
        assertFalse(_both(webauthn, key, m, _waSig(pk, a, _clientData(keccak256("x"), "}"))), "other challenge");
        bytes memory create = abi.encodePacked(
            '{"type":"webauthn.create","challenge":"', Base64.encodeURL(abi.encodePacked(m)), '","origin":"o"}'
        );
        assertFalse(_both(webauthn, key, m, _waSig(pk, a, create)), "webauthn.create");
    }

    function test_WebAuthnNegatives() public view {
        uint256 pk = 0xC0FFEE;
        bytes memory key = _waKey(pk);
        bytes32 m = _msg(UAKinds.WEBAUTHN_P256, keccak256("d"));
        bytes memory a = _authData(RP_ID_HASH, 0x05);
        bytes memory cd = _clientData(m, "}");
        bytes memory sig = _waSig(pk, a, cd);
        assertTrue(_both(webauthn, key, m, sig));

        assertFalse(_both(webauthn, key, m, _waSig(pk, _authData(keccak256("other rp"), 0x05), cd)), "rpIdHash");
        assertFalse(_both(webauthn, key, m, _waSig(pk, _authData(RP_ID_HASH, 0x04), cd)), "no UP");
        assertFalse(_both(webauthn, key, m, _waSig(pk, _authData(RP_ID_HASH, 0x01), cd)), "no UV");
        assertFalse(_both(webauthn, key, m, _waSig(pk, _slice(a, 36), cd)), "authData 36");
        (bytes memory ad, string memory c, uint256 r, uint256 s) = abi.decode(sig, (bytes, string, uint256, uint256));
        assertFalse(_both(webauthn, key, m, abi.encode(ad, c, r, N_P256 - s)), "high-s");
        assertFalse(_both(webauthn, key, m, abi.encode(ad, c, r ^ 1, s)), "mutated r");
        assertFalse(_both(webauthn, key, m, abi.encode(abi.encodePacked(ad, hex"00"), c, r, s)), "authData changed");
        assertFalse(_both(webauthn, key, UAKinds.uaMessage(UAKinds.P256, UAKinds.PURPOSE_METATX, keccak256("d")), sig));
        assertFalse(_both(webauthn, _waKey(pk + 1), m, sig), "other key");
        assertFalse(_both(webauthn, _p256Key(pk), m, sig), "key 64");
        assertFalse(_both(webauthn, abi.encodePacked(key, bytes1(0)), m, sig), "key 97");
        assertFalse(_both(webauthn, abi.encodePacked(_flip(_p256Key(pk), 63), RP_ID_HASH), m, sig), "off-curve key");
        // the p256 kind's raw signature offered as a WebAuthn assertion
        assertFalse(_both(webauthn, key, m, _p256Sig(pk, m)), "raw r||s");
    }

    /// Malformed ABI blobs return false, never revert.
    function test_WebAuthnMalformedAbi() public view {
        uint256 pk = 0xC0FFEE;
        bytes memory key = _waKey(pk);
        bytes32 m = _msg(UAKinds.WEBAUTHN_P256, keccak256("d"));
        bytes memory sig = _waSig(pk, _authData(RP_ID_HASH, 0x05), _clientData(m, "}"));
        assertFalse(_both(webauthn, key, m, ""), "empty");
        assertFalse(_both(webauthn, key, m, new bytes(127)), "127 bytes");
        assertFalse(_both(webauthn, key, m, new bytes(128)), "zero head");
        assertFalse(_both(webauthn, key, m, _setWord(sig, 0, type(uint256).max)), "offset max");
        assertFalse(_both(webauthn, key, m, _setWord(sig, 0, 1 << 255)), "offset 2^255");
        assertFalse(_both(webauthn, key, m, _setWord(sig, 32, sig.length)), "offset = length");
        assertFalse(_both(webauthn, key, m, _setWord(sig, 32, sig.length - 31)), "offset leaves < 32");
        assertFalse(_both(webauthn, key, m, _setWord(sig, 128, type(uint256).max)), "authData length max");
        assertFalse(_both(webauthn, key, m, _setWord(sig, 128, sig.length)), "authData length past end");
        uint256 cdOff = _word(sig, 32);
        assertFalse(_both(webauthn, key, m, _setWord(sig, cdOff, type(uint256).max - 31)), "clientData length wraps");
        uint256 cdEnd = cdOff + 32 + _word(sig, cdOff);
        assertFalse(_both(webauthn, key, m, _slice(sig, cdEnd - 1)), "truncated clientData");
        assertFalse(
            _both(webauthn, key, m, abi.encodePacked(keccak256("a"), keccak256("b"), keccak256("c"), keccak256("d"))),
            "junk"
        );
    }

    function _setWord(bytes memory b, uint256 o, uint256 w) internal pure returns (bytes memory c) {
        c = bytes.concat(b);
        assembly ("memory-safe") {
            mstore(add(add(c, 32), o), w)
        }
    }

    // ------------------------------------------------------------------ bip340

    function test_Bip340ChallengeTag() public pure {
        assertEq(
            sha256("BIP0340/challenge"), bytes32(0x7bb52d7a9fef58323eb1bf7a407db382d2f3f2d81bb1224f49fe518f6d48d37c)
        );
        assertEq((P_K1 + 1) / 4, 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c);
    }

    struct Bip {
        bytes32 key;
        bytes32 message;
        bytes sig;
        bool ok;
    }

    /// bitcoin/bips bip-0340/test-vectors.csv, rows 0–14 (the 32-byte messages; 15–18 have other lengths).
    function _bipVectors() internal pure returns (Bip[15] memory v) {
        v[0] = Bip(
            hex"f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9",
            hex"0000000000000000000000000000000000000000000000000000000000000000",
            hex"e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0",
            true
        ); // valid
        v[1] = Bip(
            hex"dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
            hex"243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
            hex"6896bd60eeae296db48a229ff71dfe071bde413e6d43f917dc8dcf8c78de33418906d11ac976abccb20b091292bff4ea897efcb639ea871cfa95f6de339e4b0a",
            true
        ); // valid
        v[2] = Bip(
            hex"dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8",
            hex"7e2d58d8b3bcdf1abadec7829054f90dda9805aab56c77333024b9d0a508b75c",
            hex"5831aaeed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1bab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7",
            true
        ); // valid
        v[3] = Bip(
            hex"25d1dff95105f5253c4022f628a996ad3a0d95fbf21d468a1b33f8c160d8f517",
            hex"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            hex"7eb0509757e246f19449885651611cb965ecc1a187dd51b64fda1edc9637d5ec97582b9cb13db3933705b32ba982af5af25fd78881ebb32771fc5922efc66ea3",
            true
        ); // test fails if msg is reduced modulo p or n
        v[4] = Bip(
            hex"d69c3509bb99e412e68b0fe8544e72837dfa30746d8be2aa65975f29d22dc7b9",
            hex"4df3c3f68fcc83b27e9d42c90431a72499f17875c81a599b566c9889b9696703",
            hex"00000000000000000000003b78ce563f89a0ed9414f5aa28ad0d96d6795f9c6376afb1548af603b3eb45c9f8207dee1060cb71c04e80f593060b07d28308d7f4",
            true
        ); // valid
        v[5] = Bip(
            hex"eefdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34",
            hex"243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
            hex"6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e17776969e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b",
            false
        ); // public key not on the curve
        v[6] = Bip(
            hex"dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
            hex"243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
            hex"fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a14602975563cc27944640ac607cd107ae10923d9ef7a73c643e166be5ebeafa34b1ac553e2",
            false
        ); // has_even_y(R) is false
        v[7] = Bip(
            hex"dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
            hex"243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
            hex"1fa62e331edbc21c394792d2ab1100a7b432b013df3f6ff4f99fcb33e0e1515f28890b3edb6e7189b630448b515ce4f8622a954cfe545735aaea5134fccdb2bd",
            false
        ); // negated message
        v[8] = Bip(
            hex"dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
            hex"243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
            hex"6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e177769961764b3aa9b2ffcb6ef947b6887a226e8d7c93e00c5ed0c1834ff0d0c2e6da6",
            false
        ); // negated s value
        v[9] = Bip(
            hex"dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
            hex"243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
            hex"0000000000000000000000000000000000000000000000000000000000000000123dda8328af9c23a94c1feecfd123ba4fb73476f0d594dcb65c6425bd186051",
            false
        ); // sG - eP is infinite (fails if has_even_y(inf) is defined as true and x(inf) as 0)
        v[10] = Bip(
            hex"dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
            hex"243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
            hex"00000000000000000000000000000000000000000000000000000000000000017615fbaf5ae28864013c099742deadb4dba87f11ac6754f93780d5a1837cf197",
            false
        ); // sG - eP is infinite (fails if has_even_y(inf) is defined as true and x(inf) as 1)
        v[11] = Bip(
            hex"dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
            hex"243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
            hex"4a298dacae57395a15d0795ddbfd1dcb564da82b0f269bc70a74f8220429ba1d69e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b",
            false
        ); // sig[0:32] is not an X coordinate on the curve
        v[12] = Bip(
            hex"dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
            hex"243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
            hex"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f69e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b",
            false
        ); // sig[0:32] is equal to field size
        v[13] = Bip(
            hex"dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659",
            hex"243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
            hex"6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e177769fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            false
        ); // sig[32:64] is equal to curve order
        v[14] = Bip(
            hex"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30",
            hex"243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89",
            hex"6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e17776969e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b",
            false
        ); // public key is not a valid X coordinate because it exceeds the field size
    }

    function test_Bip340OfficialVectors() public view {
        Bip[15] memory v = _bipVectors();
        for (uint256 i; i < v.length; ++i) {
            assertEq(_both(bip340, abi.encodePacked(v[i].key), v[i].message, v[i].sig), v[i].ok, vm.toString(i));
        }
    }

    function testFuzz_Bip340Valid(uint256 d, uint256 k, bytes32 digest) public {
        d = bound(d, 1, N_K1 - 1);
        k = bound(k, 1, N_K1 - 1);
        bytes32 m = _msg(UAKinds.BIP340, digest);
        (bytes memory key, bytes memory sig) = _bipSign(d, k, m);
        assertTrue(_both(bip340, key, m, sig));
        assertFalse(_both(bip340, key, m, _flip(sig, 63)), "mutated s");
        assertFalse(_both(bip340, key, _msg(UAKinds.BIP340, ~digest), sig), "other message");
    }

    function test_Bip340Negatives() public {
        bytes32 m = _msg(UAKinds.BIP340, keccak256("d"));
        (bytes memory key, bytes memory sig) = _bipSign(0xD00D, 0x1234, m);
        assertTrue(_both(bip340, key, m, sig));
        (uint256 r, uint256 s) = abi.decode(sig, (uint256, uint256));
        assertFalse(_both(bip340, key, m, abi.encodePacked(r, N_K1)), "s = n");
        assertFalse(_both(bip340, key, m, abi.encodePacked(r, N_K1 - s)), "negated s");
        assertFalse(_both(bip340, key, m, abi.encodePacked(P_K1, s)), "r = p");
        assertFalse(_both(bip340, abi.encodePacked(P_K1), m, sig), "key = p");
        assertFalse(_both(bip340, abi.encodePacked(uint256(5)), m, sig), "key off curve (x = 5)");
        assertFalse(_both(bip340, new bytes(32), m, sig), "key 0");
        assertFalse(_both(bip340, abi.encodePacked(key, bytes1(0)), m, sig), "key 33");
        assertFalse(_both(bip340, abi.encodePacked(bytes1(0x02), key), m, sig), "compressed key");
        assertFalse(_both(bip340, key, m, abi.encodePacked(sig, bytes1(0))), "sig 65");
        assertFalse(_both(bip340, key, m, _slice(sig, 63)), "sig 63");
        assertFalse(_both(bip340, key, m, ""), "sig empty");
        assertFalse(_both(bip340, key, m, new bytes(64)), "sig 0");
        assertFalse(_both(bip340, key, UAKinds.uaMessage(UAKinds.BIP340, UAKinds.PURPOSE_POP, keccak256("d")), sig));
    }

    // ------------------------------------------------------------------ gas

    function test_Gas() public {
        bytes32 d = keccak256("gas");
        uint256 pk = 0xA11CE;
        bytes32 m = _msg(UAKinds.P256, d);
        bytes memory key = _p256Key(pk);
        bytes memory sig = _p256Sig(pk, m);
        _report("p256", p256, key, m, sig, _flip(sig, 40), CAP_P256);

        m = _msg(UAKinds.WEBAUTHN_P256, d);
        key = _waKey(pk);
        bytes memory a = _authData(RP_ID_HASH, 0x05);
        sig = _waSig(pk, a, _clientData(m, ',"crossOrigin":false}'));
        (bytes memory ad, string memory c, uint256 r, uint256 s) = abi.decode(sig, (bytes, string, uint256, uint256));
        _report("webauthn-p256", webauthn, key, m, sig, abi.encode(ad, c, r ^ 1, s), CAP_WEBAUTHN);

        m = _msg(UAKinds.BIP340, d);
        (key, sig) = _bipSign(0xD00D, 0x1234, m);
        _report("bip340", bip340, key, m, sig, _flip(sig, 63), CAP_BIP340);
    }

    function _report(
        string memory name,
        IUAPopVerifier v,
        bytes memory key,
        bytes32 m,
        bytes memory sig,
        bytes memory bad,
        uint256 cap
    ) internal view {
        v.verify(key, m, sig); // warm the verifier account: the numbers below exclude the 2,500 cold-access surcharge
        (uint256 gv, bool okv) = _gas(v, false, key, m, sig);
        (uint256 gp, bool okp) = _gas(v, true, key, m, sig);
        (uint256 gb, bool okb) = _gas(v, false, key, m, bad);
        assertTrue(okv && okp && !okb, name);
        console.log(name);
        console.log("  verify / verifyPop (valid), verify (invalid sig):", gv, gp, gb);
        assertLt(gv, cap, name);
        assertLt(gp, cap, name);
        assertLt(gb, cap, name);
    }

    /// With the probed precompile an invalid P-256 signature costs one precompile call, not the Solidity verifier.
    function test_P256InvalidCheapWithPrecompile() public {
        vm.skip(!p256.PRECOMPILE());
        uint256 pk = 0xA11CE;
        bytes32 m = _msg(UAKinds.P256, keccak256("gas"));
        bytes memory key = _p256Key(pk);
        p256.verify(key, m, ""); // warm
        (uint256 g, bool ok) = _gas(p256, false, key, m, _flip(_p256Sig(pk, m), 40));
        assertFalse(ok);
        assertLt(g, 20_000, "p256 invalid");
        m = _msg(UAKinds.WEBAUTHN_P256, keccak256("gas"));
        bytes memory wsig = _waSig(pk, _authData(RP_ID_HASH, 0x05), _clientData(m, "}"));
        (bytes memory ad, string memory c, uint256 r, uint256 s) = abi.decode(wsig, (bytes, string, uint256, uint256));
        webauthn.verify(_waKey(pk), m, ""); // warm
        (g, ok) = _gas(webauthn, false, _waKey(pk), m, abi.encode(ad, c, r ^ 1, s));
        assertFalse(ok);
        assertLt(g, 40_000, "webauthn invalid");
    }
}
```

- [ ] **Step 10: Test.** From `smartcontracts/evm`:
  - `../../scripts/capped forge test --match-path 'test/ua/verifiers/*' -vv` — `16 tests passed, 0 failed, 0 skipped`;
    logs `p256 … 10645 10741 10645`, `webauthn-p256 … 24663 24754 24663`, `bip340 … 11236 11305 11236`,
    `p256 Solidity path verify (valid / invalid): 251247 250547`, `webauthn Solidity path verify (valid / invalid): 266770 265407`
    (twice: `empty 0x100`, `0x100 answers 1`).
  - `FOUNDRY_EVM_VERSION=prague ../../scripts/capped forge test --match-path 'test/ua/verifiers/*' -vv` (no 0x100 at all) —
    `15 tests passed, 0 failed, 1 skipped` (`test_P256InvalidCheapWithPrecompile`); `p256 … 249310 249406 247210`,
    `webauthn-p256 … 258433 258524 258915`, `bip340 … 8537 8606 8537`.
  - `../../scripts/capped forge test --match-path 'test/account/*'` — `51 tests passed, 0 failed` (SmartKeyAccount unchanged
    in behaviour).
  - `../../scripts/capped forge build src/ua/MlDsa.sol src/ua/SlhDsa.sol src/ua/FnDsa.sol src/ua/PqUA.sol --force` — `Compiler run successful!`
- [ ] **Step 11: Commit.**

```bash
cd /home/ha/work/ainative/scaas
/usr/bin/git add smartcontracts/evm/src/ua/IUAVerifier.sol smartcontracts/evm/src/common/WebAuthnClientData.sol \
  smartcontracts/evm/src/ua/verifiers/P256Precompile.sol smartcontracts/evm/src/ua/verifiers/P256Verifier.sol \
  smartcontracts/evm/src/ua/verifiers/WebAuthnP256Verifier.sol smartcontracts/evm/src/ua/verifiers/Bip340Verifier.sol \
  smartcontracts/evm/test/ua/verifiers/EccVerifiers.t.sol smartcontracts/evm/src/ua/PqUA.sol \
  smartcontracts/evm/src/ua/MlDsa.sol smartcontracts/evm/src/ua/SlhDsa.sol smartcontracts/evm/src/ua/FnDsa.sol \
  smartcontracts/evm/src/account/SmartKeyAccount.sol
/usr/bin/git commit -m "UA-2a T2: ECC verifiers: P-256, WebAuthn-P256, BIP-340

IUAKindVerifier moves to src/ua/IUAVerifier.sol beside the new IUAPopVerifier;
P256Verifier and WebAuthnP256Verifier on a constructor-probed P256VERIFY with
the OZ Solidity verifier otherwise (SmartKeyAccount clientDataJSON grammar
shared through WebAuthnClientData, origin-free); Bip340Verifier (ecrecover
trick, one MODEXP lift); tests on signatures.json, the official BIP-340
vectors, malformed inputs, the probe and the Solidity path, and gas.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 3: Pairing-curve verifiers: Schnorr bn254/BLS12-381, BLS min-sig BLS12-381/bn254

**Files:**
- Create: `smartcontracts/evm/src/common/CurveSigs.sol` (Schnorr / BLS min-sig with the tag, DST or label as a parameter — the
  former private `UniversalAccountRegistry._schnorr`, `_blsBn254` and the inline BLS12-381 check, extracted)
- Create: `smartcontracts/evm/src/ua/verifiers/PairingVerifiers.sol` (`UASafeVerifier`, `SchnorrBn254Verifier`,
  `SchnorrBls12381Verifier`, `BlsMinSigBls12381Verifier`, `BlsMinSigBn254Verifier`)
- Create: `smartcontracts/evm/test/ua/verifiers/PairingVerifiers.t.sol`
- Modify: `smartcontracts/evm/src/registry/UniversalAccountRegistry.sol` (use `CurveSigs`; behaviour unchanged except a
  malformed bn254 Schnorr `R`/`Y` now gives `false` → `InvalidProofOfPossession` instead of bubbling `G1Bn254.BadPoint`)

**Interfaces:**
- Consumes: `IUAPopVerifier is IUAKindVerifier` from `src/ua/IUAVerifier.sol` (Task 2);
  `smartcontracts/vectors/ua/signatures.json` (Task 1; the four `derived` rows of kinds 0x0104–0x0107) and
  `kinds.json` (UA-1, its `invalid` rows); `UAKinds` (`uaOf`, `uaMessage`, `popDigest`, `UAVerifyGas`), `ZetherTranscript.hashToScalar`,
  `G1Bn254`, `G1Bls12381`, `Bls12381.verifyMinSig`, `HashToCurve.hashToG1`.
- Produces: four stateless verifier contracts for the registry's per-kind verifier immutables; each answers
  `verify` / `verifyPop` with false (never a revert) on any malformed input, bounded by its public `CHECK_GAS`
  (40 k / 60 k / 180 k / 330 k). **Registry constraint:** `verifyCap[kind] ≥ CHECK_GAS + CHECK_GAS/63 + 5 000` (+ the call),
  else `verify` reverts `UAKinds.UAVerifyGas()`; proposed starting caps 50 k / 70 k / 200 k / 345 k (asserted by
  `test_proposedCapsSuffice`). `CurveSigs.schnorr/blsBn254/bls12381` for UA-2c (MuSig2/FROST bn254 reuse `schnorr`).

- [ ] **Step 1: Extract the curve signature checks into `CurveSigs`.** Create `smartcontracts/evm/src/common/CurveSigs.sol`:

```solidity
// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.20;

import {Bls12381} from "./Bls12381.sol";
import {HashToCurve} from "./HashToCurve.sol";
import {ZetherTranscript} from "../zether/ZetherTranscript.sol";
import {G1Bn254, G1Bls12381} from "../zether/ZetherCurves.sol";

/// @title Schnorr on bn254 / BLS12-381 G1 and BLS min-sig on both curves, with the tag / DST / label as a parameter.
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** Shared by `UniversalAccountRegistry` (Zether tags) and the UA
///         verifiers (`src/ua/verifiers/`, UA tags). Returns false on a wrong signature and on a malformed bn254 G1 point
///         (checked in Solidity). A malformed BLS12-381 point (non-canonical, off the curve, outside the subgroup) or a
///         malformed bn254 G2 key makes a precompile fail — consuming all the gas it was given — and the curve helpers
///         **revert** (`G1Bls12381.BadPoint`, `Bls12381.PrecompileFailed`) or answer false (bn254 pairing); callers
///         that must answer false within a bound wrap the call with a gas cap (`UASafeVerifier`).
library CurveSigs {
    /// bn254 G2 generator, EIP-197 order: x_im, x_re, y_im, y_re.
    bytes internal constant BN254_G2 = abi.encodePacked(
        uint256(11559732032986387107991004021392285783925812861821192530917403151452391805634),
        uint256(10857046999023057135944570762232829481370756359578518086990519993285655852781),
        uint256(4082367875863433681332203403145435568316851327593401208105741076214120093531),
        uint256(8495653923123431417604973247489272438418190587263600148770280649306958101930)
    );

    /// @notice Schnorr on the curve of `y` (64 B bn254, 128 B BLS12-381): `sig = R ‖ z`,
    ///         `e = hashToScalar(keccak256(tag ‖ R ‖ Y ‖ m), r)`, accept iff `z < r`, `e ≠ 0`, `R ≠ O`, `Y ≠ O` and
    ///         `[z]G − R − [e]Y == O` (one MSM; on BLS12-381 G1MSM also checks `R`, `Y` in the subgroup).
    function schnorr(bytes memory tag, bytes memory y, bytes32 m, bytes memory sig) internal view returns (bool) {
        uint256 p = y.length;
        if ((p != 64 && p != 128) || sig.length != p + 32) return false;
        bytes memory rPt = new bytes(p);
        uint256 z;
        assembly ("memory-safe") {
            for { let i := 0 } lt(i, p) { i := add(i, 32) } { mstore(add(add(rPt, 32), i), mload(add(add(sig, 32), i))) }
            z := mload(add(add(sig, 32), p))
        }
        // bn254: R, Y canonical and on the curve (cofactor 1), so the precompiles below cannot fail.
        if (p == 64 && !(_bnG1(rPt) && _bnG1(y))) return false;
        uint256 r = p == 64 ? G1Bn254.R : G1Bls12381.R;
        uint256 e = ZetherTranscript.hashToScalar(keccak256(abi.encodePacked(tag, rPt, y, m)), r);
        if (z >= r || e == 0 || _isZero(rPt) || _isZero(y)) return false;
        uint256[] memory sc = new uint256[](3);
        (sc[0], sc[1], sc[2]) = (z, r - 1, r - e);
        bytes memory out = p == 64
            ? G1Bn254.msm(bytes.concat(G1Bn254.generator(), rPt, y), sc)
            : G1Bls12381.msm(bytes.concat(G1Bls12381.generator(), rPt, y), sc);
        return _isZero(out);
    }

    /// @notice BLS min-sig on bn254: `e(−sig, G2) · e(H(m), pk) == 1`, `H = G1Bn254.mapToG1(label ‖ m)`
    ///         (try-and-increment: unbounded, ~5.2 k gas per extra iteration under EIP-7883). `sig` canonical, on the curve,
    ///         ≠ O; the pairing precompile checks `pk` canonical, on the twist and in G2.
    function blsBn254(bytes memory label, bytes memory pk, bytes32 m, bytes memory sig) internal view returns (bool) {
        if (pk.length != 128 || !_bnG1(sig)) return false;
        bytes memory h = G1Bn254.mapToG1(abi.encodePacked(label, m));
        (bool ok, bytes memory out) = address(0x08).staticcall(bytes.concat(G1Bn254.neg(sig), BN254_G2, h, pk));
        return ok && out.length == 32 && abi.decode(out, (uint256)) == 1;
    }

    /// @notice BLS min-sig on BLS12-381: `H = HashToCurve.hashToG1(m, dst)`, `sig ≠ O`, `Bls12381.verifyMinSig`
    ///         (PAIRING_CHECK checks `sig` and `pk` canonical, on curve and in their subgroups, EIP-2537).
    function bls12381(bytes memory dst, bytes memory pk, bytes32 m, bytes memory sig) internal view returns (bool) {
        if (sig.length != 128 || pk.length != 256 || _isZero(sig)) return false;
        return Bls12381.verifyMinSig(HashToCurve.hashToG1(abi.encodePacked(m), dst), pk, sig);
    }

    /// bn254 G1: 64 bytes, canonical, on `y² = x³ + 3` (excludes O = (0, 0)); pure, so a bad point costs no
    /// failing precompile (which would consume all the gas it was given).
    function _bnG1(bytes memory a) private pure returns (bool) {
        if (a.length != 64) return false;
        (uint256 x, uint256 y) = abi.decode(a, (uint256, uint256));
        uint256 q = G1Bn254.P;
        return x < q && y < q && mulmod(y, y, q) == addmod(mulmod(mulmod(x, x, q), x, q), 3, q);
    }

    function _isZero(bytes memory b) private pure returns (bool) {
        return keccak256(b) == keccak256(new bytes(b.length));
    }
}
```

- [ ] **Step 2: Point `UniversalAccountRegistry` at `CurveSigs`.** Apply (from the repo root, `git apply -p1`):

```diff
--- a/smartcontracts/evm/src/registry/UniversalAccountRegistry.sol
+++ b/smartcontracts/evm/src/registry/UniversalAccountRegistry.sol
@@ -5,9 +5,8 @@
 import {AuthScheme} from "../common/AuthScheme.sol";
 import {MultiSig} from "../common/MultiSig.sol";
 import {Bls12381} from "../common/Bls12381.sol";
-import {HashToCurve} from "../common/HashToCurve.sol";
+import {CurveSigs} from "../common/CurveSigs.sol";
 import {ZetherTypes} from "../zether/ZetherTypes.sol";
-import {ZetherTranscript} from "../zether/ZetherTranscript.sol";
 import {ZetherSafety} from "../zether/ZetherSafety.sol";
 import {G1Bn254, G1Bls12381} from "../zether/ZetherCurves.sol";
 import {IUniversalAccountRegistry} from "./IUniversalAccountRegistry.sol";
@@ -40,13 +39,6 @@
     bytes private constant BLS_BN254_POP = "SCAAS-BLS-BN254-POP-V1";
     bytes private constant BLS381_DST_SIG = "SCAAS-AUTH-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_SIG_";
     bytes private constant BLS381_DST_POP = "SCAAS-AUTH-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";
-    /// bn254 G2 generator, thứ tự EIP-197: x_im, x_re, y_im, y_re.
-    bytes private constant BN254_G2 = abi.encodePacked(
-        uint256(11559732032986387107991004021392285783925812861821192530917403151452391805634),
-        uint256(10857046999023057135944570762232829481370756359578518086990519993285655852781),
-        uint256(4082367875863433681332203403145435568316851327593401208105741076214120093531),
-        uint256(8495653923123431417604973247489272438418190587263600148770280649306958101930)
-    );
 
     mapping(ZetherTypes.UA => Account) private _accounts;
     mapping(address => ZetherTypes.UA) public links;
@@ -205,9 +197,7 @@
         }
         if (s == AuthScheme.BLS_BN254) return _blsBn254(abi.decode(d, (bytes)), m, sig, pop);
         if (s == AuthScheme.BLS_12381) {
-            if (sig.length != 128 || _isZero(sig)) return false;
-            bytes memory h = HashToCurve.hashToG1(abi.encodePacked(m), pop ? BLS381_DST_POP : BLS381_DST_SIG);
-            return Bls12381.verifyMinSig(h, abi.decode(d, (bytes)), sig);
+            return CurveSigs.bls12381(pop ? BLS381_DST_POP : BLS381_DST_SIG, abi.decode(d, (bytes)), m, sig);
         }
         // SMART_ACCOUNT_1271 — trần gas như ERC20MetaTx
         (bool ok, bytes memory ret) = abi.decode(d, (address)).staticcall{gas: 50_000}(
@@ -218,34 +208,11 @@
 
     /// @dev Schnorr §11.1 trên đường cong của `y`: `[z]G − R − [e]Y == O`.
     function _schnorr(bytes memory y, bytes32 m, bytes memory sig) private view returns (bool) {
-        uint256 p = y.length;
-        if ((p != 64 && p != 128) || sig.length != p + 32) return false;
-        bytes memory rPt = new bytes(p);
-        uint256 z;
-        assembly ("memory-safe") {
-            for { let i := 0 } lt(i, p) { i := add(i, 32) } { mstore(add(add(rPt, 32), i), mload(add(add(sig, 32), i))) }
-            z := mload(add(add(sig, 32), p))
-        }
-        uint256 r = p == 64 ? G1Bn254.R : G1Bls12381.R;
-        uint256 e = ZetherTranscript.hashToScalar(keccak256(abi.encodePacked(SCHNORR_TAG, rPt, y, m)), r);
-        if (z >= r || e == 0 || keccak256(rPt) == keccak256(new bytes(p)) || keccak256(y) == keccak256(new bytes(p))) {
-            return false;
-        }
-        uint256[] memory sc = new uint256[](3);
-        (sc[0], sc[1], sc[2]) = (z, r - 1, r - e);
-        bytes memory out = p == 64
-            ? G1Bn254.msm(bytes.concat(G1Bn254.generator(), rPt, y), sc)
-            : G1Bls12381.msm(bytes.concat(G1Bls12381.generator(), rPt, y), sc);
-        return keccak256(out) == keccak256(new bytes(p));
+        return CurveSigs.schnorr(SCHNORR_TAG, y, m, sig);
     }
 
     /// @dev BLS min-sig trên bn254: `e(−sig, G2) · e(H(m), pk) == 1`, H = try-and-increment (§3.1, §11.2).
     function _blsBn254(bytes memory pk, bytes32 m, bytes memory sig, bool pop) private view returns (bool) {
-        if (sig.length != 64 || !G1Bn254.isValid(sig) || G1Bn254.isIdentity(sig)) return false;
-        bytes memory h = G1Bn254.mapToG1(abi.encodePacked(pop ? BLS_BN254_POP : BLS_BN254_SIG, m));
-        (bool ok, bytes memory out) = address(0x08).staticcall(
-            bytes.concat(G1Bn254.neg(sig), BN254_G2, h, pk)
-        );
-        return ok && out.length == 32 && abi.decode(out, (uint256)) == 1;
+        return CurveSigs.blsBn254(pop ? BLS_BN254_POP : BLS_BN254_SIG, pk, m, sig);
     }
 }
```

- [ ] **Step 3: The four verifiers.** Create `smartcontracts/evm/src/ua/verifiers/PairingVerifiers.sol`:

```solidity
// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {IUAPopVerifier} from "../IUAVerifier.sol";
import {UAKinds} from "../UAKinds.sol";
import {CurveSigs} from "../../common/CurveSigs.sol";

/// @title A UA verifier that answers false instead of reverting (accounts.md §1.9, CTR-UA-17).
/// @notice `verify` / `verifyPop` run `check` through an external self-call capped at `CHECK_GAS` under `try`, so a
///         revert inside a curve helper (off-curve, non-canonical or out-of-subgroup point: the precompile fails and
///         `G1Bn254` / `G1Bls12381` / `Bls12381` revert) or an out-of-gas inside it becomes `false`. The cap matters: a
///         failing EIP-196/197/2537 precompile consumes all the gas it was given, and the curve helpers forward `gas()`,
///         so without it a malformed point would burn 63/64 of the caller's gas. A call that cannot give `check` its
///         full `CHECK_GAS` reverts `UAKinds.UAVerifyGas` (a statement about the gas, never `false` about the key).
///         Worst case of any call: `CHECK_GAS` + the wrapper. **UNAUDITED — NOT FOR PRODUCTION FUNDS.**
abstract contract UASafeVerifier is IUAPopVerifier {
    uint256 public immutable CHECK_GAS;

    constructor(uint256 checkGas) {
        CHECK_GAS = checkGas;
    }

    function verify(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool) {
        return _safe(keyData, message, sig, false);
    }

    function verifyPop(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool) {
        return _safe(keyData, message, sig, true);
    }

    /// @notice The unguarded check (`pop` selects the PoP domain); may revert on malformed points. External only so
    ///         `verify` / `verifyPop` can catch its reverts; it is as safe to call as they are, minus that guarantee.
    function check(bytes calldata keyData, bytes32 message, bytes calldata sig, bool pop)
        external view virtual returns (bool);

    function _safe(bytes calldata keyData, bytes32 message, bytes calldata sig, bool pop) private view returns (bool) {
        if (gasleft() < CHECK_GAS + CHECK_GAS / 63 + 5_000) revert UAKinds.UAVerifyGas();
        try this.check{gas: CHECK_GAS}(keyData, message, sig, pop) returns (bool ok) {
            return ok;
        } catch {
            return false;
        }
    }
}

bytes constant SCHNORR_TAG = "scaas.ua.schnorr.v1";

/// @title `schnorr-bn254` (0x0104): `Y` (64), `sig = R ‖ z` (96); `verifyPop` = `verify`.
contract SchnorrBn254Verifier is UASafeVerifier {
    /// valid ≈ 27 k inside `check` (3 ECMUL + 3 ECADD); R, Y checked in Solidity, so no failing precompile.
    constructor() UASafeVerifier(40_000) {}

    function check(bytes calldata keyData, bytes32 message, bytes calldata sig, bool)
        external view override returns (bool)
    {
        return keyData.length == 64 && CurveSigs.schnorr(SCHNORR_TAG, keyData, message, sig);
    }
}

/// @title `schnorr-bls12381` (0x0105): `Y` (128, EIP-2537), `sig = R ‖ z` (160); `verifyPop` = `verify`.
contract SchnorrBls12381Verifier is UASafeVerifier {
    /// valid ≈ 39 k inside `check` (G1MSM k = 3); a malformed R / Y fails G1MSM and burns the cap.
    constructor() UASafeVerifier(60_000) {}

    function check(bytes calldata keyData, bytes32 message, bytes calldata sig, bool)
        external view override returns (bool)
    {
        return keyData.length == 128 && CurveSigs.schnorr(SCHNORR_TAG, keyData, message, sig);
    }
}

/// @title `bls12381-minsig` (0x0106): `pk ∈ G2` (256, EIP-2537), `sig ∈ G1` (128); RFC 9380 hash-to-G1 of `ua_msg`.
contract BlsMinSigBls12381Verifier is UASafeVerifier {
    /// valid ≈ 157 k inside `check` (2 MAP_FP_TO_G1, G1ADD, PAIRING_CHECK k = 2); a malformed sig burns the cap.
    constructor() UASafeVerifier(180_000) {}

    bytes internal constant DST_SIG = "SCAAS-UA-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_SIG_";
    bytes internal constant DST_POP = "SCAAS-UA-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";

    function check(bytes calldata keyData, bytes32 message, bytes calldata sig, bool pop)
        external view override returns (bool)
    {
        return CurveSigs.bls12381(pop ? DST_POP : DST_SIG, keyData, message, sig);
    }
}

/// @title `bls-bn254-minsig` (0x0107): `pk ∈ G2` (128, EIP-197 order), `sig ∈ G1` (64); try-and-increment `mapToG1`.
contract BlsMinSigBn254Verifier is UASafeVerifier {
    /// valid ≈ 123 k + 5.2 k per extra `mapToG1` iteration; 330 k leaves ~39 extra iterations (an honest message
    /// needs more with probability ~2^-39; it then fails closed and the signer re-signs another digest).
    constructor() UASafeVerifier(330_000) {}

    bytes internal constant LABEL_SIG = "SCAAS-UA-BLS-BN254-SIG-V1";
    bytes internal constant LABEL_POP = "SCAAS-UA-BLS-BN254-POP-V1";

    function check(bytes calldata keyData, bytes32 message, bytes calldata sig, bool pop)
        external view override returns (bool)
    {
        return CurveSigs.blsBn254(pop ? LABEL_POP : LABEL_SIG, keyData, message, sig);
    }
}
```

- [ ] **Step 4: Tests.** Create `smartcontracts/evm/test/ua/verifiers/PairingVerifiers.t.sol`:

```solidity
// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {UAKinds} from "../../../src/ua/UAKinds.sol";
import {
    UASafeVerifier,
    SchnorrBn254Verifier,
    SchnorrBls12381Verifier,
    BlsMinSigBls12381Verifier,
    BlsMinSigBn254Verifier
} from "../../../src/ua/verifiers/PairingVerifiers.sol";
import {G1Bn254, G1Bls12381} from "../../../src/zether/ZetherCurves.sol";

/// The pairing-curve UA verifiers (accounts.md §1.9) against smartcontracts/vectors/ua/signatures.json (valid PoPs and
/// signatures, the generator's negatives) and kinds.json (every invalid key data of the four kinds, reused as malformed
/// keys and malformed signature points). Gas per verifier is printed and checked against the §1.15 caps.
contract PairingVerifiersTest is Test {
    string internal constant SIGS = "../vectors/ua/signatures.json";
    string internal constant KINDS = "../vectors/ua/kinds.json";
    string internal constant STRUCTURES = "../vectors/ua/structures.json";

    mapping(uint16 => UASafeVerifier) internal verifier;
    uint16[4] internal kinds =
        [UAKinds.SCHNORR_BN254, UAKinds.SCHNORR_BLS12381, UAKinds.BLS12381_MINSIG, UAKinds.BLS_BN254_MINSIG];

    struct Row {
        uint16 kind;
        bytes keyData;
        bytes32 ua;
        bytes32 popMsg;
        bytes popSig;
        bytes32 popOtherMsg;
        bytes popOtherSig;
        bytes32 metaMsg;
        bytes metaSig;
        bytes32 memberMsg;
        bytes memberSig;
        string pfx; // ".derived[i]"
    }

    function setUp() public {
        verifier[UAKinds.SCHNORR_BN254] = new SchnorrBn254Verifier();
        verifier[UAKinds.SCHNORR_BLS12381] = new SchnorrBls12381Verifier();
        verifier[UAKinds.BLS12381_MINSIG] = new BlsMinSigBls12381Verifier();
        verifier[UAKinds.BLS_BN254_MINSIG] = new BlsMinSigBn254Verifier();
    }

    // ----- vector access -----

    function _isOurs(uint16 k) internal pure returns (bool) {
        return k >= UAKinds.SCHNORR_BN254 && k <= UAKinds.BLS_BN254_MINSIG;
    }

    function _rows() internal view returns (Row[] memory rows) {
        string memory j = vm.readFile(SIGS);
        uint256 n;
        while (vm.keyExistsJson(j, string.concat(".derived[", vm.toString(n), "]"))) ++n;
        rows = new Row[](4);
        uint256 got;
        for (uint256 i; i < n; ++i) {
            string memory pfx = string.concat(".derived[", vm.toString(i), "]");
            uint16 k = uint16(vm.parseJsonUint(j, string.concat(pfx, ".kind")));
            if (!_isOurs(k)) continue;
            Row memory r = rows[k - UAKinds.SCHNORR_BN254]; // indexed by kind, whatever the file order
            ++got;
            r.kind = k;
            r.pfx = pfx;
            r.keyData = vm.parseJsonBytes(j, string.concat(pfx, ".keyData"));
            r.ua = vm.parseJsonBytes32(j, string.concat(pfx, ".ua"));
            r.popMsg = vm.parseJsonBytes32(j, string.concat(pfx, ".pop.message"));
            r.popSig = vm.parseJsonBytes(j, string.concat(pfx, ".pop.sig"));
            r.popOtherMsg = vm.parseJsonBytes32(j, string.concat(pfx, ".popOther.message"));
            r.popOtherSig = vm.parseJsonBytes(j, string.concat(pfx, ".popOther.sig"));
            for (uint256 s; vm.keyExistsJson(j, string.concat(pfx, ".sigs[", vm.toString(s), "]")); ++s) {
                string memory sa = string.concat(pfx, ".sigs[", vm.toString(s), "]");
                bytes32 purpose = keccak256(bytes(vm.parseJsonString(j, string.concat(sa, ".purpose"))));
                bytes32 m = vm.parseJsonBytes32(j, string.concat(sa, ".message"));
                bytes memory sig = vm.parseJsonBytes(j, string.concat(sa, ".sig"));
                if (purpose == keccak256("metatx")) (r.metaMsg, r.metaSig) = (m, sig);
                else if (purpose == keccak256("member")) (r.memberMsg, r.memberSig) = (m, sig);
            }
        }
        assertEq(got, 4, "signatures.json: the four pairing-curve kinds");
    }

    function _ctxPopDigest(string memory c, bytes32 ua) internal view returns (bytes32) {
        string memory s = vm.readFile(STRUCTURES);
        string memory pfx = string.concat(".contexts.", c);
        return UAKinds.popDigest(
            UAKinds.chainKeyHash(vm.parseJsonUint(s, string.concat(pfx, ".chainId"))),
            vm.parseJsonBytes32(s, string.concat(pfx, ".chainUid")),
            vm.parseJsonAddress(s, string.concat(pfx, ".registry")),
            ua,
            bytes32(0)
        );
    }

    function _bls(uint16 k) internal pure returns (bool) {
        return k == UAKinds.BLS12381_MINSIG || k == UAKinds.BLS_BN254_MINSIG;
    }

    /// The invalid key data rows of kinds.json for `k`.
    function _invalidKeys(uint16 k) internal view returns (bytes[] memory out, string[] memory why) {
        string memory j = vm.readFile(KINDS);
        uint256 n;
        while (vm.keyExistsJson(j, string.concat(".invalid[", vm.toString(n), "]"))) ++n;
        out = new bytes[](n);
        why = new string[](n);
        uint256 got;
        for (uint256 i; i < n; ++i) {
            string memory pfx = string.concat(".invalid[", vm.toString(i), "]");
            if (vm.parseJsonUint(j, string.concat(pfx, ".kind")) != k) continue;
            why[got] = vm.parseJsonString(j, string.concat(pfx, ".reason"));
            out[got++] = vm.parseJsonBytes(j, string.concat(pfx, ".keyData"));
        }
        assembly ("memory-safe") {
            mstore(out, got)
            mstore(why, got)
        }
    }

    function _both(UASafeVerifier v, bytes memory key, bytes32 m, bytes memory sig) internal view returns (bool) {
        return v.verify(key, m, sig) || v.verifyPop(key, m, sig);
    }

    // ----- valid -----

    function test_vectorsBindIdsAndMessages() public view {
        Row[] memory rows = _rows();
        string memory j = vm.readFile(SIGS);
        bytes32 digest = vm.parseJsonBytes32(j, ".digest");
        for (uint256 i; i < rows.length; ++i) {
            Row memory r = rows[i];
            assertEq(UAKinds.uaOf(r.kind, r.keyData), r.ua, "ua");
            assertEq(r.popMsg, UAKinds.uaMessage(r.kind, UAKinds.PURPOSE_POP, _ctxPopDigest("A", r.ua)), "pop A");
            assertEq(r.popOtherMsg, UAKinds.uaMessage(r.kind, UAKinds.PURPOSE_POP, _ctxPopDigest("B", r.ua)), "pop B");
            assertEq(r.metaMsg, UAKinds.uaMessage(r.kind, UAKinds.PURPOSE_METATX, digest), "metatx");
            UAKinds.validateKeyData(r.kind, r.keyData, false);
        }
    }

    function test_validPopsAndSignatures() public view {
        Row[] memory rows = _rows();
        for (uint256 i; i < rows.length; ++i) {
            Row memory r = rows[i];
            UASafeVerifier v = verifier[r.kind];
            assertTrue(v.verifyPop(r.keyData, r.popMsg, r.popSig), "pop A");
            assertTrue(v.verifyPop(r.keyData, r.popOtherMsg, r.popOtherSig), "pop B");
            assertTrue(v.verify(r.keyData, r.metaMsg, r.metaSig), "metatx");
            assertTrue(v.verify(r.keyData, r.memberMsg, r.memberSig), "member");
            // Schnorr: verifyPop == verify; BLS: the PoP domain is separate (CTR-UA-07).
            assertEq(v.verify(r.keyData, r.popMsg, r.popSig), !_bls(r.kind), "pop via verify");
            assertEq(v.verifyPop(r.keyData, r.metaMsg, r.metaSig), !_bls(r.kind), "metatx via verifyPop");
            // PoP of context A does not verify for context B's message.
            assertFalse(v.verifyPop(r.keyData, r.popOtherMsg, r.popSig), "pop A on B");
        }
    }

    // ----- generator negatives (wrong purpose, wrong kind tag, other chain uid, mutated, cross DST) -----

    function test_negatives() public view {
        string memory j = vm.readFile(SIGS);
        Row[] memory rows = _rows();
        uint256 seen;
        for (uint256 i; i < rows.length; ++i) {
            Row memory r = rows[i];
            UASafeVerifier v = verifier[r.kind];
            bool sigAsPop;
            bool popAsSig;
            for (uint256 n; vm.keyExistsJson(j, string.concat(r.pfx, ".negatives[", vm.toString(n), "]")); ++n) {
                string memory pfx = string.concat(r.pfx, ".negatives[", vm.toString(n), "]");
                string memory nm = vm.parseJsonString(j, string.concat(pfx, ".name"));
                bool pop = vm.parseJsonBool(j, string.concat(pfx, ".verifyPop"));
                bytes32 m = vm.parseJsonBytes32(j, string.concat(pfx, ".message"));
                bytes memory sig = vm.parseJsonBytes(j, string.concat(pfx, ".sig"));
                bool got = pop ? v.verifyPop(r.keyData, m, sig) : v.verify(r.keyData, m, sig);
                assertFalse(got, string.concat(UAKinds.name(r.kind), " ", nm));
                if (keccak256(bytes(nm)) == keccak256("sig-dst-as-pop")) sigAsPop = true;
                if (keccak256(bytes(nm)) == keccak256("pop-dst-as-sig")) popAsSig = true;
                ++seen;
            }
            if (_bls(r.kind)) assertTrue(sigAsPop && popAsSig, "BLS cross-DST negatives present");
        }
        assertGt(seen, 16);
    }

    // ----- malformed keys: every kinds.json invalid row, plus the other curve's key -----

    function test_malformedKeys() public view {
        Row[] memory rows = _rows();
        for (uint256 i; i < rows.length; ++i) {
            Row memory r = rows[i];
            (bytes[] memory bad, string[] memory why) = _invalidKeys(r.kind);
            assertGt(bad.length, 5);
            for (uint256 b; b < bad.length; ++b) {
                assertFalse(_both(verifier[r.kind], bad[b], r.metaMsg, r.metaSig), why[b]);
                assertFalse(_both(verifier[r.kind], bad[b], r.popMsg, r.popSig), why[b]);
            }
        }
        // Each Schnorr verifier is bound to its curve: the other curve's valid key + signature fails.
        (Row memory sn, Row memory sb) = (rows[0], rows[1]);
        assertFalse(_both(verifier[sn.kind], sb.keyData, sb.metaMsg, sb.metaSig), "bls schnorr via bn254 verifier");
        assertFalse(_both(verifier[sb.kind], sn.keyData, sn.metaMsg, sn.metaSig), "bn254 schnorr via bls verifier");
    }

    // ----- malformed signatures -----

    function test_malformedSignatureLengths() public view {
        Row[] memory rows = _rows();
        for (uint256 i; i < rows.length; ++i) {
            Row memory r = rows[i];
            UASafeVerifier v = verifier[r.kind];
            assertFalse(_both(v, r.keyData, r.metaMsg, ""), "empty");
            assertFalse(_both(v, r.keyData, r.metaMsg, _cut(r.metaSig, 1)), "short");
            assertFalse(_both(v, r.keyData, r.metaMsg, bytes.concat(r.metaSig, hex"00")), "long");
            assertFalse(_both(v, r.keyData, r.metaMsg, new bytes(r.metaSig.length)), "all zero");
            assertFalse(_both(v, "", r.metaMsg, r.metaSig), "empty key");
            assertFalse(_both(v, bytes.concat(r.keyData, hex"00"), r.metaMsg, r.metaSig), "long key");
        }
    }

    /// Schnorr: z ≥ r, R = O, R malformed (every invalid G1 encoding of the curve from kinds.json).
    function test_malformedSchnorr() public view {
        Row[] memory rows = _rows();
        for (uint256 i; i < 2; ++i) {
            Row memory r = rows[i];
            UASafeVerifier v = verifier[r.kind];
            uint256 p = r.keyData.length;
            uint256 order = p == 64 ? G1Bn254.R : G1Bls12381.R;
            bytes memory rPt = _cut(r.metaSig, 32);
            uint256 z = uint256(bytes32(_tail(r.metaSig, 32)));
            assertTrue(v.verify(r.keyData, r.metaMsg, bytes.concat(rPt, bytes32(z))));
            assertFalse(v.verify(r.keyData, r.metaMsg, bytes.concat(rPt, bytes32(z + order))), "z + r");
            assertFalse(v.verify(r.keyData, r.metaMsg, bytes.concat(rPt, bytes32(order))), "z = r");
            assertFalse(v.verify(r.keyData, r.metaMsg, bytes.concat(rPt, bytes32(type(uint256).max))), "z = 2^256-1");
            assertFalse(v.verify(r.keyData, r.metaMsg, bytes.concat(new bytes(p), bytes32(z))), "R = O");
            assertFalse(v.verify(r.keyData, r.metaMsg, bytes.concat(rPt, bytes32(0))), "z = 0");
            (bytes[] memory bad, string[] memory why) = _invalidKeys(r.kind);
            for (uint256 b; b < bad.length; ++b) {
                if (bad[b].length != p) continue;
                assertFalse(v.verify(r.keyData, r.metaMsg, bytes.concat(bad[b], bytes32(z))), why[b]);
            }
        }
    }

    /// BLS: the G1 signature replaced by every invalid G1 encoding of its curve (kinds.json rows of the same-curve
    /// Schnorr kind: identity, non-zero padding, x = p, non-canonical, off the curve, outside the subgroup).
    function test_malformedBlsSignatures() public view {
        Row[] memory rows = _rows();
        for (uint256 i = 2; i < 4; ++i) {
            Row memory r = rows[i];
            uint16 g1Kind = r.kind == UAKinds.BLS12381_MINSIG ? UAKinds.SCHNORR_BLS12381 : UAKinds.SCHNORR_BN254;
            (bytes[] memory bad, string[] memory why) = _invalidKeys(g1Kind);
            uint256 n;
            for (uint256 b; b < bad.length; ++b) {
                if (bad[b].length != r.metaSig.length) continue;
                assertFalse(_both(verifier[r.kind], r.keyData, r.metaMsg, bad[b]), why[b]);
                assertFalse(_both(verifier[r.kind], r.keyData, r.popMsg, bad[b]), why[b]);
                ++n;
            }
            assertGt(n, 3);
            // −sig is a valid point and a wrong signature.
            bytes memory negSig =
                r.kind == UAKinds.BLS12381_MINSIG ? G1Bls12381.neg(r.metaSig) : G1Bn254.neg(r.metaSig);
            assertFalse(_both(verifier[r.kind], r.keyData, r.metaMsg, negSig), "-sig");
        }
    }

    /// EIP-2537 in this EVM: G1ADD accepts an on-curve point outside the subgroup, PAIRING_CHECK refuses it — the
    /// BLS12-381 verifier relies on the pairing for the subgroup check of the signature.
    function test_bls12381SubgroupCheckIsInThePairing() public view {
        bytes memory off = _offSubgroupBlsG1();
        (bool ok, bytes memory out) = address(0x0b).staticcall{gas: 50_000}(bytes.concat(off, new bytes(128)));
        assertTrue(ok && out.length == 128, "G1ADD accepts it (on curve only)");
        Row[] memory rows = _rows();
        (ok,) = address(0x0f).staticcall{gas: 200_000}(bytes.concat(off, rows[2].keyData));
        assertFalse(ok, "PAIRING_CHECK refuses it");
    }

    /// `check` reverts on a malformed BLS12-381 point (bn254 G1 points are checked in Solidity: false, no revert);
    /// `verify` / `verifyPop` turn the revert into false.
    function test_checkRevertsVerifyAnswersFalse() public {
        Row[] memory rows = _rows();
        Row memory r = rows[1];
        bytes memory offSubgroupR = bytes.concat(_offSubgroupBlsG1(), _tail(r.metaSig, 32));
        vm.expectRevert(G1Bls12381.BadPoint.selector);
        verifier[r.kind].check{gas: 100_000}(r.keyData, r.metaMsg, offSubgroupR, false);
        assertFalse(verifier[r.kind].verify(r.keyData, r.metaMsg, offSubgroupR));
        Row memory b = rows[0];
        bytes memory offCurveR = bytes.concat(bytes32(uint256(1)), bytes32(uint256(3)), _tail(b.metaSig, 32));
        assertFalse(verifier[b.kind].check(b.keyData, b.metaMsg, offCurveR, false));
    }

    /// Starved calls never pass: below `CHECK_GAS` + 1/64 they revert `UAVerifyGas`; with enough gas they pass.
    function test_starvedVerifyNeverTrue() public {
        Row[] memory rows = _rows();
        for (uint256 i; i < rows.length; ++i) {
            Row memory r = rows[i];
            UASafeVerifier v = verifier[r.kind];
            uint256 need = v.CHECK_GAS() + v.CHECK_GAS() / 63 + 5_000;
            for (uint256 g = 3_000; g < need; g += need / 7) {
                try v.verify{gas: g}(r.keyData, r.metaMsg, r.metaSig) returns (bool ok) {
                    assertFalse(ok, "starved verify passed");
                } catch {}
            }
            vm.expectRevert(UAKinds.UAVerifyGas.selector);
            v.verify{gas: need - 1_000}(r.keyData, r.metaMsg, r.metaSig);
            assertTrue(v.verify{gas: need + 10_000}(r.keyData, r.metaMsg, r.metaSig), "enough gas");
        }
    }

    /// bn254 `mapToG1` is try-and-increment: gas per extra iteration, and how many iterations `CHECK_GAS` allows
    /// (an honest message needs more than k with probability ~2^-k).
    function test_bn254MapToG1Iterations() public view {
        (uint256 minIt, uint256 minGas, uint256 maxIt, uint256 maxGas) = (type(uint256).max, 0, 0, 0);
        for (uint256 i; i < 64; ++i) {
            bytes memory prefix = abi.encodePacked("SCAAS-UA-BLS-BN254-SIG-V1", keccak256(abi.encode(i)));
            uint256 g = gasleft();
            G1Bn254.mapToG1(prefix);
            g -= gasleft();
            uint256 it = _iterations(prefix);
            if (it < minIt) (minIt, minGas) = (it, g);
            if (it > maxIt) (maxIt, maxGas) = (it, g);
        }
        uint256 per = (maxGas - minGas) / (maxIt - minIt);
        console.log("bn254 mapToG1: iterations min/max", minIt, maxIt);
        console.log("  gas at min / per extra iteration", minGas, per);
        Row[] memory rows = _rows();
        Row memory r = rows[3];
        uint256 valid = _gas(verifier[r.kind], false, r.keyData, r.memberMsg, r.memberSig);
        console.log("  CHECK_GAS headroom in iterations ", (verifier[r.kind].CHECK_GAS() + 3_000 - valid) / per);
    }

    function _iterations(bytes memory prefix) internal view returns (uint256 n) {
        uint256 p = G1Bn254.P;
        for (uint32 ctr;; ++ctr) {
            uint256 x = uint256(keccak256(abi.encodePacked(prefix, ctr))) % p;
            uint256 rhs = addmod(mulmod(mulmod(x, x, p), x, p), 3, p);
            (, bytes memory y) = address(0x05).staticcall(abi.encode(32, 32, 32, rhs, (p + 1) / 4, p));
            uint256 yy = abi.decode(y, (uint256));
            if (mulmod(yy, yy, p) == rhs) return ctr + 1;
        }
    }

    // ----- gas (accounts.md §1.15 caps: schnorr-bn254 50 k, bls12381-minsig 200 k; the other two have none yet) -----

    function test_gas() public view {
        Row[] memory rows = _rows();
        uint256[4] memory caps = [uint256(50_000), 0, 200_000, 0];
        for (uint256 i; i < rows.length; ++i) {
            Row memory r = rows[i];
            UASafeVerifier v = verifier[r.kind];
            uint256 gv = _gas(v, false, r.keyData, r.metaMsg, r.metaSig);
            uint256 gp = _gas(v, true, r.keyData, r.popMsg, r.popSig);
            uint256 gm = _gas(v, false, r.keyData, r.memberMsg, r.memberSig);
            // Rejecting worst case: a well-formed signature for another message runs the full check.
            uint256 gw = _gas(v, false, r.keyData, r.memberMsg, r.metaSig);
            // Rejecting malformed early: all-zero signature.
            uint256 gz = _gas(v, false, r.keyData, r.metaMsg, new bytes(r.metaSig.length));
            // Rejecting a malformed point (a failing precompile burns what it is given): bounded by CHECK_GAS.
            bytes memory offCurve = r.metaSig.length == 64 || r.metaSig.length == 96
                ? bytes.concat(bytes32(uint256(1)), bytes32(uint256(3)), _tail(r.metaSig, r.metaSig.length - 64))
                : bytes.concat(_cut(r.metaSig, r.metaSig.length - 64), bytes32(0), bytes32(uint256(5)), _tail(r.metaSig, r.metaSig.length - 128));
            uint256 gb = _gas(v, false, r.keyData, r.metaMsg, offCurve);
            console.log(UAKinds.name(r.kind));
            console.log("  verify metatx(cold) / member", gv, gm);
            console.log("  verifyPop                   ", gp);
            console.log("  reject wrong msg / zero sig ", gw, gz);
            console.log("  reject off-curve point      ", gb, v.CHECK_GAS());
            assertLe(gb, v.CHECK_GAS() + 10_000, "malformed point bounded by CHECK_GAS");
            uint256 worst = _max(_max(_max(gv, gp), _max(gm, gw)), gb);
            console.log("  worst                       ", worst);
            uint256 gc = gasleft();
            v.check(r.keyData, r.memberMsg, r.memberSig, false);
            console.log("  wrapper overhead (try + self-call)", gm - (gc - gasleft()));
            if (caps[i] != 0) assertLe(worst, caps[i], "over the 1.15 cap");
        }
    }

    /// Proposed `verifyCap` starting values (§1.15 has 50 k and 200 k; schnorr-bls12381 / bls-bn254-minsig: none). A cap
    /// must be at least `CHECK_GAS + CHECK_GAS / 63 + 5 000` plus the call itself, or `verify` reverts `UAVerifyGas`.
    function test_proposedCapsSuffice() public view {
        Row[] memory rows = _rows();
        uint256[4] memory caps = [uint256(50_000), 70_000, 200_000, 345_000];
        for (uint256 i; i < rows.length; ++i) {
            Row memory r = rows[i];
            UASafeVerifier v = verifier[r.kind];
            assertGe(caps[i], v.CHECK_GAS() + v.CHECK_GAS() / 63 + 5_000, "cap below the CHECK_GAS floor");
            assertTrue(v.verify{gas: caps[i]}(r.keyData, r.metaMsg, r.metaSig), "metatx at cap");
            assertTrue(v.verifyPop{gas: caps[i]}(r.keyData, r.popMsg, r.popSig), "pop at cap");
        }
    }

    function _gas(UASafeVerifier v, bool pop, bytes memory k, bytes32 m, bytes memory s)
        internal view returns (uint256 used)
    {
        uint256 g = gasleft();
        pop ? v.verifyPop(k, m, s) : v.verify(k, m, s);
        used = g - gasleft();
    }

    function _offSubgroupBlsG1() internal view returns (bytes memory off) {
        (bytes[] memory bad, string[] memory why) = _invalidKeys(UAKinds.SCHNORR_BLS12381);
        for (uint256 b; b < bad.length; ++b) {
            if (keccak256(bytes(why[b])) == keccak256("outside the subgroup")) off = bad[b];
        }
        assertEq(off.length, 128);
    }

    // ----- bytes helpers -----

    function _max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a : b;
    }

    function _cut(bytes memory b, uint256 n) internal pure returns (bytes memory c) {
        c = new bytes(b.length - n);
        for (uint256 i; i < c.length; ++i) c[i] = b[i];
    }

    function _tail(bytes memory b, uint256 n) internal pure returns (bytes memory c) {
        c = new bytes(n);
        for (uint256 i; i < n; ++i) c[i] = b[b.length - n + i];
    }
}
```

- [ ] **Step 5: Test.** `cd smartcontracts/evm && ../../scripts/capped forge test --match-path 'test/ua/verifiers/PairingVerifiers.t.sol' -vv` —
  `13 passed; 0 failed`; `test_gas` logs (signatures.json rev1):

```
schnorr-bn254      verify 31359 (cold) / 28859   verifyPop 28871    reject wrong msg 28859, zero 5162, off-curve 5162
schnorr-bls12381   verify 43226 (cold) / 40726   verifyPop 40738    reject wrong msg 40726, zero 6580, off-curve 61910
bls12381-minsig    verify 161286 (cold) / 158786 verifyPop 158788   reject wrong msg 158786, zero 4676, off-curve 180807
bls-bn254-minsig   verify 148405 (cold) / 125026 verifyPop 130357   reject wrong msg 125026, zero 4639, off-curve 4639
wrapper overhead (try + self-call) ≈ 1.9 k; bn254 mapToG1 5.2 k per extra iteration, CHECK_GAS headroom 39 iterations
```

- [ ] **Step 6: Regression of the extracted helpers.** `cd smartcontracts/evm && ../../scripts/capped forge test --match-path 'test/zether/UniversalAccountRegistry.t.sol'` —
  `22 passed; 0 failed` (incl. `test_selfSchnorrAcceptsReferenceSignature`, `test_blsBn254Auth`, `test_bls12381Auth`,
  `test_invalidKeysRejected`). Then the whole suite once: `../../scripts/capped forge test` — no new failures.

- [ ] **Step 7: Commit.**

```bash
/usr/bin/git add smartcontracts/evm/src/common/CurveSigs.sol smartcontracts/evm/src/ua/verifiers/PairingVerifiers.sol \
  smartcontracts/evm/test/ua/verifiers/PairingVerifiers.t.sol smartcontracts/evm/src/registry/UniversalAccountRegistry.sol
/usr/bin/git commit -m "UA-2a T3: pairing-curve verifiers (Schnorr bn254/BLS12-381, BLS min-sig BLS12-381/bn254)

CurveSigs: the registry's private _schnorr/_blsBn254/BLS12-381 checks as a library with the tag/DST/label
as a parameter. UASafeVerifier: verify/verifyPop through a CHECK_GAS-capped try self-call, so malformed
points answer false within a fixed bound (a failing precompile consumes all the gas it is given).

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 4: UARegistry core — registry, derived, native, msig, generations

**Files:**
- Create: `smartcontracts/evm/src/ua/IUARegistry.sol`
- Create: `smartcontracts/evm/src/ua/UARegistry.sol`
- Create: `smartcontracts/evm/test/ua/UARegistryBase.sol`
- Create: `smartcontracts/evm/test/ua/UARegistry.t.sol`

**Interfaces:**
- Consumes: `src/ua/UAKinds.sol` (UA-1: tags, ids, keyHash, `uaMessage`, `popDigest`, `chainKeyHash`, `uaAuthDigest`,
  `memberDigest`, `validateKeyData`, sets, `UAVerifyGas`); `src/common/SaltedEIP712.sol` (domain with salt = chainUid,
  ERC-5267, `ChainUidZero`); `src/common/SigCheck.sol` (`ERC1271_GAS`, `GAS_MARGIN`); OZ `ECDSA`, `IERC1271`, `IERC5267`,
  `Clones` (test); **`src/ua/IUAVerifier.sol` from Task 2** (`IUAKindVerifier.verify`,
  `IUAPopVerifier is IUAKindVerifier { verifyPop }`, PQ files importing it); vectors `smartcontracts/vectors/ua/kinds.json`,
  `structures.json`.
- Produces: `IUARegistry` (§1.8 surface for UA-2a, `is IERC5267`; `requireZetherAuthorized` comes with UA-3) and
  `UARegistry(bytes32 chainUid, address predecessor, bool hederaNative, uint64 verifyBudget, address smartKeyAccountImpl,
  bool msig, KindConfig[] kinds)` with `KindConfig{uint16 kind; address verifier; uint64 cap}`,
  `MemberSig{uint16 index; bytes keyData; bytes sig}`, constructor error `UAConfig(uint16)`, `MSIG_MEMBER_GAS = 35_000`,
  public `chainKeyHash()`. Enabled-kind slots: 0x0100–0x0107 + `msig`; everything else `UAKindDisabled`.

- [ ] **Step 1: Interface.** `smartcontracts/evm/src/ua/IUARegistry.sol` (complete):

```solidity
// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {IERC5267} from "@openzeppelin/contracts/interfaces/IERC5267.sol";

/// @title The UA registry (accounts.md §1.8): monotonic, admin-free records of derived UAs and the one entry point
///        `requireAuthorized` that tokens call for every UA signature.
/// @notice `eip712Domain()` (ERC-5267) comes from `IERC5267`: fields `0x1f`, name "SCaaS UARegistry", version = the
///         generation in decimal, salt = `chainUid`. `requireZetherAuthorized` joins this interface with the Zether
///         kinds (UA-3).
interface IUARegistry is IERC5267 {
    struct Record {
        uint16 kind;
        uint40 registeredAt;
        address keyPtr; // ≠ 0 only for stored kinds (UA-2c MuSig2/FROST, P6c PQ)
    }

    event UARegistered(bytes32 indexed ua, uint16 indexed kind, bytes keyData, bytes32 authRef);

    error UAKindDisabled(uint16 kind); // not enabled in this generation (incl. kinds a predecessor offers)
    error UAKeyData(uint16 kind); // non-canonical, curve, subgroup, identity, ordering, threshold, cap bound
    error UAIdInNativeSpace(bytes32 ua);
    error UAAlreadyRegistered(bytes32 ua);
    error UAKeyInUse(bytes32 keyHash, bytes32 owner); // layer 2
    error UAMemberUnknown(bytes32 member); // structure member not native/registered, or kind ∉ MEMBER
    error UAAuthRef(bytes32 authRef); // Zether: not native/SIGNING, same-curve BLS, PQ rule; others: ≠ 0
    error UAPoP();
    error UAUnauthorized(bytes32 ua); // also: ua is ZETHER or unregistered

    function generation() external view returns (uint8); // 1 or 2
    function predecessor() external view returns (address);
    function kindEnabled(uint16 kind) external view returns (bool);
    function verifyCap(uint16 kind) external view returns (uint64); // measured per chain
    function verifyBudget() external view returns (uint64); // UA_VERIFY_BUDGET of this chain
    function chainUid() external view returns (bytes32); // genesis hash, constructor immutable
    function hederaNative() external view returns (bool); // Hedera profile: 0x0003 ∈ MEMBER
    function uaOf(uint16 kind, bytes calldata keyData) external pure returns (bytes32);
    function keyHashOf(uint16 kind, bytes calldata keyData) external pure returns (bytes32); // 0 for structures
    function popDigest(bytes32 ua, bytes32 authRef) external view returns (bytes32);
    function uaMessage(uint16 kind, bytes32 purposeTag, bytes32 digest) external pure returns (bytes32);
    /// EIP-712 digest of UAAuth(ua, purposeTag, digest) under this registry's domain: what native signers sign.
    function uaAuthDigest(bytes32 ua, bytes32 purposeTag, bytes32 digest) external view returns (bytes32);

    function register(uint16 kind, bytes calldata keyData, bytes calldata pop, bytes32 authRef, bytes calldata authPop)
        external
        returns (bytes32 ua); // authPop empty iff authRef == 0

    function recordOf(bytes32 ua) external view returns (Record memory r, bytes32 authRef);
    function kindOf(bytes32 ua) external view returns (uint16); // 0 = not registered (native ids too)
    function isRegistered(bytes32 ua) external view returns (bool);
    function keyOwner(bytes32 keyHash) external view returns (bytes32);

    /// Reverts UAUnauthorized unless `auth` authorizes `digest` for `ua` under `purposeTag`.
    /// Native ids (ua >> 160 == 0): ECDSA low-s (EOA) or ERC-1271 (50 k cap; 400 k for SmartKeyAccount clones, by the
    ///   immutable clone codehash) over uaAuthDigest(ua, purposeTag, digest) — never over the raw digest.
    ///   Classified by code at call time: empty ⇒ ECDSA; 7702 designator ⇒ ECDSA, else 1271; other ⇒ 1271.
    /// Derived SIGNING: auth = abi.encode(bytes keyData, bytes sig); keyData empty for stored kinds.
    ///   msig: sig = abi.encode(MemberSig[]), MemberSig{uint16 index; bytes keyData; bytes sig}.
    /// ZETHER or unregistered: UAUnauthorized.
    function requireAuthorized(bytes32 ua, bytes32 purposeTag, bytes32 digest, bytes calldata auth) external view;
}
```

- [ ] **Step 2: Registry.** Kind table as one `uint256` immutable per verifiable kind (`verifier | cap << 160`), filled
  from the `KindConfig[]` argument: no SLOAD / EXTCODECOPY at verify time; kinds without registry code (MuSig2/FROST,
  PQ, Zether) refused by the constructor so later sub-plans add slot + code and redeploy. `smartcontracts/evm/src/ua/UARegistry.sol` (complete):

```solidity
// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {SaltedEIP712} from "../common/SaltedEIP712.sol";
import {SigCheck} from "../common/SigCheck.sol";
import {IUARegistry} from "./IUARegistry.sol";
import {IUAKindVerifier, IUAPopVerifier} from "./IUAVerifier.sol";
import {UAKinds} from "./UAKinds.sol";

/// @title UA registry, UA-2a scope (accounts.md §1.8): the single-key kinds 0x0100–0x0107, the structure `msig`, native
///        EVM ids, generations.
/// @notice Monotonic and admin-free (CTR-UA-15): no owner, no setter, no `payable`, a record never changes. `register`
///         derives every record field from `keyData` (CTR-UA-07), so anyone may relay it. Every verifier `staticcall` is
///         capped at the kind's `verifyCap` and counts only exactly 32 bytes equal to 1; a caller that leaves too little
///         gas for the cap gets `UAVerifyGas`, never a pass (T-AUTH-4).
///
///         Kind table: one `uint256` immutable per kind this code can verify, `verifier | cap << 160` (0 = disabled):
///         read with no SLOAD and no EXTCODECOPY. Kinds whose registry code is not written yet — MuSig2/FROST and the
///         stored-key path (UA-2c), PQ (P6c), Zether (UA-3) — are refused by the constructor; each later sub-plan adds
///         its slot and code and redeploys (all chains are test chains). `ed25519` (0x0102) has its slot already: it is
///         a plain single-key kind, so UA-2b only deploys its verifier and passes it here.
///
///         Gen 2 (`predecessor ≠ 0`) reads gen 1 for `UAAlreadyRegistered` / `UAKeyInUse` / `kindOf` / `keyOwner` /
///         `recordOf` and hands records it does not hold, and members whose kind it does not enable, to gen 1's
///         `requireAuthorized`. Its constructor refuses every single-key kind whose keyHash group gen 1 enables.
///
///         Open in UA-2a: HIP-632 (`hedera-native` members' 64-byte ed25519 signatures) needs a non-static CALL, which a
///         `view` `requireAuthorized` cannot make; such members verify as ECDSA/1271 only.
///         UNAUDITED — NOT FOR PRODUCTION FUNDS.
contract UARegistry is IUARegistry, SaltedEIP712 {
    struct KindConfig {
        uint16 kind;
        address verifier;
        uint64 cap;
    }

    struct MemberSig {
        uint16 index;
        bytes keyData;
        bytes sig;
    }

    /// @notice A constructor argument is refused (kind outside this code's table, duplicate, verifier without code, cap
    ///         0 or above the budget, a keyHash group the predecessor enables, a predecessor of another chain/profile).
    error UAConfig(uint16 kind);

    uint256 internal constant SMART_KEY_1271_GAS = 400_000;
    /// @notice Registration bound for `msig` (register step 4): gas per member beyond its verifier's cap — MemberSig
    ///         decoding, `uaOf`, `uaMessage`, the call, the gen-1 hand-off (measured worst: 14.1 k warm), two cold
    ///         accounts (5.2 k), and what the caller must hold for the largest cap (400 k / 63 + 5 k); rounded up.
    ///         `UAGas.t.sol` `test_T_GAS_msigMemberOverhead` keeps it honest.
    uint256 internal constant MSIG_MEMBER_GAS = 35_000;

    uint8 public immutable generation;
    address public immutable predecessor;
    bool public immutable hederaNative;
    uint64 public immutable verifyBudget;
    /// @notice `keccak256("evm:" ‖ decimal(block.chainid))`, computed at deploy (CTR-UA-07).
    bytes32 public immutable chainKeyHash;
    bytes32 private immutable _SMART_KEY_CLONE_CODEHASH;

    uint256 private immutable _CFG0; // 0x0100 webauthn-p256
    uint256 private immutable _CFG1; // 0x0101 p256
    uint256 private immutable _CFG2; // 0x0102 ed25519 (UA-2b)
    uint256 private immutable _CFG3; // 0x0103 bip340
    uint256 private immutable _CFG4; // 0x0104 schnorr-bn254
    uint256 private immutable _CFG5; // 0x0105 schnorr-bls12381
    uint256 private immutable _CFG6; // 0x0106 bls12381-minsig
    uint256 private immutable _CFG7; // 0x0107 bls-bn254-minsig
    uint256 private immutable _CFG_MSIG; // 0x0120: address(this) | verifyBudget << 160

    mapping(bytes32 ua => Record) private _records;
    mapping(bytes32 keyHash => bytes32) private _keyOwner;

    /// @param chainUid_ the chain's genesis hash (≠ 0, `SaltedEIP712.ChainUidZero`).
    /// @param predecessor_ 0 for generation 1, else the chain's gen-1 registry.
    /// @param smartKeyAccountImpl_ the chain's `SmartKeyAccount` implementation (0 = none): its EIP-1167 clones get the
    ///        400 k ERC-1271 cap.
    /// @param msig_ enables the structure kind `msig`.
    /// @param kinds_ the enabled single-key kinds with their verifier and measured cap.
    constructor(
        bytes32 chainUid_,
        address predecessor_,
        bool hederaNative_,
        uint64 verifyBudget_,
        address smartKeyAccountImpl_,
        bool msig_,
        KindConfig[] memory kinds_
    ) SaltedEIP712("SCaaS UARegistry", predecessor_ == address(0) ? "1" : "2", chainUid_) {
        if (verifyBudget_ == 0) revert UAConfig(0);
        if (predecessor_ != address(0)) {
            IUARegistry p = IUARegistry(predecessor_);
            if (p.generation() != 1 || p.chainUid() != chainUid_ || p.hederaNative() != hederaNative_) {
                revert UAConfig(0);
            }
        }
        uint256[8] memory k;
        for (uint256 i; i < kinds_.length; ++i) {
            KindConfig memory c = kinds_[i];
            uint256 slot = c.kind >= 0x0100 ? c.kind - 0x0100 : 8;
            if (
                slot > 7 || k[slot] != 0 || c.verifier.code.length == 0 || c.cap == 0 || c.cap > verifyBudget_
                    || (predecessor_ != address(0) && _groupInPredecessor(predecessor_, c.kind))
            ) revert UAConfig(c.kind);
            k[slot] = uint256(uint160(c.verifier)) | uint256(c.cap) << 160;
        }
        (_CFG0, _CFG1, _CFG2, _CFG3) = (k[0], k[1], k[2], k[3]);
        (_CFG4, _CFG5, _CFG6, _CFG7) = (k[4], k[5], k[6], k[7]);
        _CFG_MSIG = msig_ ? uint256(uint160(address(this))) | uint256(verifyBudget_) << 160 : 0;

        generation = predecessor_ == address(0) ? 1 : 2;
        predecessor = predecessor_;
        hederaNative = hederaNative_;
        verifyBudget = verifyBudget_;
        chainKeyHash = UAKinds.chainKeyHash(block.chainid);
        _SMART_KEY_CLONE_CODEHASH = smartKeyAccountImpl_ == address(0)
            ? bytes32(0)
            : keccak256(
                abi.encodePacked(hex"363d3d373d3d3d363d73", smartKeyAccountImpl_, hex"5af43d82803e903d91602b57fd5bf3")
            );
    }

    // ----- views -----

    function kindEnabled(uint16 kind) external view returns (bool) {
        return uint160(_cfg(kind)) != 0;
    }

    function verifyCap(uint16 kind) public view returns (uint64) {
        return uint64(_cfg(kind) >> 160);
    }

    function chainUid() external view returns (bytes32) {
        return CHAIN_UID;
    }

    function uaOf(uint16 kind, bytes calldata keyData) external pure returns (bytes32) {
        return UAKinds.uaOf(kind, keyData);
    }

    function keyHashOf(uint16 kind, bytes calldata keyData) external pure returns (bytes32) {
        return UAKinds.keyHashOf(kind, keyData);
    }

    function popDigest(bytes32 ua, bytes32 authRef) public view returns (bytes32) {
        return UAKinds.popDigest(chainKeyHash, CHAIN_UID, address(this), ua, authRef);
    }

    function uaMessage(uint16 kind, bytes32 purposeTag, bytes32 digest) external pure returns (bytes32) {
        return UAKinds.uaMessage(kind, purposeTag, digest);
    }

    function uaAuthDigest(bytes32 ua, bytes32 purposeTag, bytes32 digest) public view returns (bytes32) {
        return UAKinds.uaAuthDigest(_domainSeparatorV4(), ua, purposeTag, digest);
    }

    /// `authRef` is always 0 here: only Zether kinds (UA-3) store one.
    function recordOf(bytes32 ua) external view returns (Record memory r, bytes32 authRef) {
        r = _records[ua];
        if (r.kind == 0 && predecessor != address(0)) return IUARegistry(predecessor).recordOf(ua);
    }

    function kindOf(bytes32 ua) public view returns (uint16 kind) {
        kind = _records[ua].kind;
        if (kind == 0 && predecessor != address(0)) kind = IUARegistry(predecessor).kindOf(ua);
    }

    function isRegistered(bytes32 ua) external view returns (bool) {
        return kindOf(ua) != 0;
    }

    function keyOwner(bytes32 keyHash) public view returns (bytes32 owner) {
        owner = _keyOwner[keyHash];
        if (owner == 0 && predecessor != address(0)) owner = IUARegistry(predecessor).keyOwner(keyHash);
    }

    // ----- register (accounts.md §1.8 steps 1–8; steps 5 and 7 reduce to "authRef == 0" in UA-2a) -----

    function register(uint16 kind, bytes calldata keyData, bytes calldata pop, bytes32 authRef, bytes calldata authPop)
        external
        returns (bytes32 ua)
    {
        uint256 cfg = _cfg(kind); // 1
        if (uint160(cfg) == 0) revert UAKindDisabled(kind);
        bool structure = kind == UAKinds.MSIG;
        bytes memory d = keyData;
        // 2. msig: the layout with the widest member set; the profile's MEMBER set is step 4 (UAMemberUnknown).
        UAKinds.validateKeyData(kind, d, structure || hederaNative);
        ua = UAKinds.uaOf(kind, d); // 3
        if (UAKinds.inNativeSpace(ua)) revert UAIdInNativeSpace(ua);
        if (kindOf(ua) != 0) revert UAAlreadyRegistered(ua);
        bytes32 kh; // 4
        if (structure) {
            _checkMembers(d);
        } else {
            kh = UAKinds.keyHashOf(kind, d);
            bytes32 owner = keyOwner(kh);
            if (owner != 0) revert UAKeyInUse(kh, owner);
        }
        if (authRef != 0 || authPop.length != 0) revert UAAuthRef(authRef); // 5, 7
        // 6. Structures have no PoP of their own (members proved theirs): `pop` must be empty.
        if (structure ? pop.length != 0 : !_popOk(cfg, kind, d, ua, pop)) revert UAPoP();
        _records[ua] = Record(kind, uint40(block.timestamp), address(0)); // 8
        if (!structure) _keyOwner[kh] = ua;
        emit UARegistered(ua, kind, keyData, 0);
    }

    function _popOk(uint256 cfg, uint16 kind, bytes memory d, bytes32 ua, bytes calldata pop)
        private
        view
        returns (bool)
    {
        bytes32 message = UAKinds.uaMessage(kind, UAKinds.PURPOSE_POP, popDigest(ua, 0));
        return _verifierCall(cfg, IUAPopVerifier.verifyPop.selector, d, message, pop);
    }

    /// Step 4 for `msig`: every member ∈ MEMBER of this profile and native or registered under its stated kind; the
    /// worst case of a minimal authorizing set fits `verifyBudget`.
    function _checkMembers(bytes memory d) private view {
        (uint256 threshold, uint256 count) = (_u16(d, 0), _u16(d, 2));
        uint256[] memory weights = new uint256[](count);
        uint256[] memory caps = new uint256[](count);
        for (uint256 i; i < count; ++i) {
            uint256 o = 4 + 36 * i;
            uint16 kind = uint16(_u16(d, o));
            bytes32 id = bytes32(_word(d, o + 2));
            if (!UAKinds.isMember(kind, hederaNative)) revert UAMemberUnknown(id);
            if (UAKinds.isNative(kind)) {
                caps[i] = _nativeCap();
            } else {
                if (kindOf(id) != kind) revert UAMemberUnknown(id);
                uint256 cfg = _cfg(kind);
                caps[i] = uint160(cfg) != 0 ? cfg >> 160 : IUARegistry(predecessor).verifyCap(kind);
            }
            weights[i] = _u16(d, o + 34);
        }
        _sort(weights);
        _sort(caps);
        uint256 c;
        for (uint256 acc; acc < threshold; ++c) {
            acc += weights[c];
        }
        uint256 worst = c * MSIG_MEMBER_GAS;
        for (uint256 i; i < c; ++i) {
            worst += caps[count - 1 - i];
        }
        if (worst > verifyBudget) revert UAKeyData(UAKinds.MSIG);
    }

    /// A native member may be (or later become, counterfactually) a `SmartKeyAccount` clone: the bound takes its cap.
    function _nativeCap() private view returns (uint256) {
        return _SMART_KEY_CLONE_CODEHASH != 0 ? SMART_KEY_1271_GAS : SigCheck.ERC1271_GAS;
    }

    // ----- requireAuthorized -----

    function requireAuthorized(bytes32 ua, bytes32 purposeTag, bytes32 digest, bytes calldata auth) external view {
        if (!_authorized(ua, purposeTag, digest, auth)) revert UAUnauthorized(ua);
    }

    function _authorized(bytes32 ua, bytes32 purposeTag, bytes32 digest, bytes calldata auth)
        private
        view
        returns (bool)
    {
        if (UAKinds.inNativeSpace(ua)) return _native(ua, purposeTag, digest, auth);
        uint16 kind = _records[ua].kind; // every kind this code registers is SIGNING
        if (kind == 0) return _viaPredecessor(ua, purposeTag, digest, auth);
        (bytes memory keyData, bytes memory sig) = abi.decode(auth, (bytes, bytes));
        return _derived(ua, kind, purposeTag, digest, keyData, sig);
    }

    /// A derived id of `kind` (taken from the record, or from the structure for members): key data against the id,
    /// then the kind's verifier, `msig`, or gen 1 for a kind this generation does not enable.
    function _derived(
        bytes32 id,
        uint16 kind,
        bytes32 purposeTag,
        bytes32 digest,
        bytes memory keyData,
        bytes memory sig
    ) private view returns (bool) {
        if (UAKinds.uaOf(kind, keyData) != id) return false;
        if (kind == UAKinds.MSIG) return _msig(id, purposeTag, digest, keyData, sig);
        uint256 cfg = _cfg(kind);
        if (uint160(cfg) == 0) return _viaPredecessor(id, purposeTag, digest, abi.encode(keyData, sig));
        return _verifierCall(
            cfg, IUAKindVerifier.verify.selector, keyData, UAKinds.uaMessage(kind, purposeTag, digest), sig
        );
    }

    /// accounts.md §1.9 `msig` row: strictly increasing member indexes, stop at the threshold (a MemberSig after it
    /// fails, which keeps the registration bound sound), `member_digest = keccak256(ua ‖ ua_msg)`.
    function _msig(bytes32 ua, bytes32 purposeTag, bytes32 digest, bytes memory d, bytes memory blob)
        private
        view
        returns (bool)
    {
        MemberSig[] memory sigs = abi.decode(blob, (MemberSig[]));
        bytes32 md = UAKinds.memberDigest(ua, UAKinds.uaMessage(UAKinds.MSIG, purposeTag, digest));
        (uint256 threshold, uint256 count) = (_u16(d, 0), _u16(d, 2));
        uint256 acc;
        uint256 next; // lowest index the next MemberSig may use
        for (uint256 i; i < sigs.length; ++i) {
            MemberSig memory s = sigs[i];
            if (acc >= threshold || s.index < next || s.index >= count) return false;
            next = uint256(s.index) + 1;
            uint256 o = 4 + 36 * uint256(s.index);
            uint16 kind = uint16(_u16(d, o));
            bytes32 id = bytes32(_word(d, o + 2));
            bool ok = UAKinds.isNative(kind)
                ? s.keyData.length == 0 && _native(id, UAKinds.PURPOSE_MEMBER, md, s.sig) // native: no key data
                : _derived(id, kind, UAKinds.PURPOSE_MEMBER, md, s.keyData, s.sig);
            if (!ok) return false;
            acc += _u16(d, o + 34);
        }
        return acc >= threshold;
    }

    /// CTR-UA-24: by code at call time. Empty ⇒ ECDSA; the 23-byte EIP-7702 designator ⇒ ECDSA, else ERC-1271 through
    /// the delegate; other code ⇒ ERC-1271 only. Always over `uaAuthDigest`. OZ `tryRecover` refuses high s and a
    /// recovered `address(0)`, so neither id 0 nor a garbage signature ever matches.
    function _native(bytes32 ua, bytes32 purposeTag, bytes32 digest, bytes memory sig) private view returns (bool) {
        address a = address(uint160(uint256(ua)));
        bytes32 h = uaAuthDigest(ua, purposeTag, digest);
        uint256 len = a.code.length;
        bool designator = len == 23 && bytes3(a.code) == 0xef0100;
        if (len == 0 || designator) {
            (address rec, ECDSA.RecoverError err,) = ECDSA.tryRecover(h, sig);
            if (err == ECDSA.RecoverError.NoError && rec == a) return true;
            if (len == 0) return false;
        }
        uint256 cap = _SMART_KEY_CLONE_CODEHASH != 0 && a.codehash == _SMART_KEY_CLONE_CODEHASH
            ? SMART_KEY_1271_GAS
            : SigCheck.ERC1271_GAS;
        return _capped(
            a,
            cap,
            abi.encodeCall(IERC1271.isValidSignature, (h, sig)),
            uint256(bytes32(IERC1271.isValidSignature.selector))
        );
    }

    function _verifierCall(uint256 cfg, bytes4 selector, bytes memory keyData, bytes32 message, bytes memory sig)
        private
        view
        returns (bool)
    {
        return _capped(address(uint160(cfg)), cfg >> 160, abi.encodeWithSelector(selector, keyData, message, sig), 1);
    }

    /// `staticcall` with exactly `cap` gas; true iff it succeeds with exactly one 32-byte word equal to `expect`.
    /// Too little gas left to hand over the full cap ⇒ `UAVerifyGas` (63/64 starvation never turns into a verdict).
    function _capped(address target, uint256 cap, bytes memory data, uint256 expect) private view returns (bool ok) {
        if (gasleft() < cap + cap / 63 + SigCheck.GAS_MARGIN) revert UAKinds.UAVerifyGas();
        assembly ("memory-safe") {
            mstore(0, 0)
            let s := staticcall(cap, target, add(data, 0x20), mload(data), 0, 0x20)
            ok := and(and(s, eq(returndatasize(), 0x20)), eq(mload(0), expect))
        }
    }

    /// Records and kinds of gen 1 are checked by gen 1 (its verifiers, its `UAAuth` domain for native members of its
    /// structures). Any revert there is a failed check.
    function _viaPredecessor(bytes32 id, bytes32 purposeTag, bytes32 digest, bytes memory auth)
        private
        view
        returns (bool)
    {
        if (predecessor == address(0)) return false;
        try IUARegistry(predecessor).requireAuthorized(id, purposeTag, digest, auth) {
            return true;
        } catch {
            return false;
        }
    }

    // ----- kind table -----

    function _cfg(uint16 kind) private view returns (uint256) {
        if (kind == UAKinds.MSIG) return _CFG_MSIG;
        if (kind < 0x0100 || kind > 0x0107) return 0;
        uint256 i = kind - 0x0100;
        if (i < 4) return i < 2 ? (i == 0 ? _CFG0 : _CFG1) : (i == 2 ? _CFG2 : _CFG3);
        return i < 6 ? (i == 4 ? _CFG4 : _CFG5) : (i == 6 ? _CFG6 : _CFG7);
    }

    /// Gen-2 rule (§1.8 "Generations"): a single-key kind whose keyHash group any kind of gen 1 enables stays in gen 1.
    function _groupInPredecessor(address pred, uint16 kind) private view returns (bool) {
        bytes32 g = keccak256(bytes(UAKinds.groupName(kind)));
        for (uint16 j = 0x0100; j <= UAKinds.PQZ_MLWE; ++j) {
            if (
                j != UAKinds.MSIG && UAKinds.isDerived(j) && keccak256(bytes(UAKinds.groupName(j))) == g
                    && IUARegistry(pred).kindEnabled(j)
            ) return true;
        }
        return false;
    }

    // ----- bytes helpers -----

    function _word(bytes memory d, uint256 o) private pure returns (uint256 w) {
        assembly ("memory-safe") {
            w := mload(add(add(d, 32), o))
        }
    }

    function _u16(bytes memory d, uint256 o) private pure returns (uint256) {
        return _word(d, o) >> 240;
    }

    /// Insertion sort, ascending (count ≤ 16).
    function _sort(uint256[] memory a) private pure {
        for (uint256 i = 1; i < a.length; ++i) {
            uint256 v = a[i];
            uint256 j = i;
            for (; j > 0 && a[j - 1] > v; --j) {
                a[j] = a[j - 1];
            }
            a[j] = v;
        }
    }
}
```

- [ ] **Step 3: Test base (stand-in verifier, wallets, gen-1 stand-in, helpers).** `smartcontracts/evm/test/ua/UARegistryBase.sol` (complete):

```solidity
// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IUAPopVerifier} from "../../src/ua/IUAVerifier.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";

/// Stand-in verifier: the "signature" over (keyData, message) is `keccak256(abi.encode(keyData, message))`, so the
/// registry's message construction (kind tag, purpose, PoP digest, member digest) is what the tests exercise.
/// Modes for T-AUTH-4: 1 revert, 2 short return (31 bytes), 3 long return (64 bytes), 4 returns 2, 5 runs out of gas.
/// `burn` gas is spent before answering (gas measurements, starvation).
contract MockVerifier is IUAPopVerifier {
    uint8 public immutable mode;
    uint256 public immutable burn;

    constructor(uint8 mode_, uint256 burn_) {
        (mode, burn) = (mode_, burn_);
    }

    function verify(bytes calldata keyData, bytes32 message, bytes calldata sig) public view returns (bool) {
        uint256 start = gasleft();
        while (start - gasleft() < burn) {}
        uint8 m = mode;
        if (m == 1) revert("mock");
        if (m == 2) {
            assembly {
                mstore(0, 1)
                return(0, 31)
            }
        }
        if (m == 3) {
            assembly {
                mstore(0, 1)
                mstore(32, 0)
                return(0, 64)
            }
        }
        if (m == 4) {
            assembly {
                mstore(0, 2)
                return(0, 32)
            }
        }
        if (m == 5) {
            assembly {
                for {} 1 {} {}
            }
        }
        return sig.length == 32 && bytes32(sig) == keccak256(abi.encode(keyData, message));
    }

    function verifyPop(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool) {
        return verify(keyData, message, sig);
    }
}

/// ERC-1271 wallet. Modes: 0 ECDSA by `owner` over the hash, 1 wrong magic, 2 revert, 3 out of gas, 4 ERC-7739-style:
/// rebuilds the hash from the registry's `eip712Domain()` (incl. salt) and the `UAAuth` struct carried in the
/// signature before checking the owner's ECDSA over it.
contract MockWallet {
    address public immutable owner;
    uint8 public immutable mode;
    uint256 public immutable burn;
    address public immutable registry;

    constructor(address owner_, uint8 mode_, uint256 burn_, address registry_) {
        (owner, mode, burn, registry) = (owner_, mode_, burn_, registry_);
    }

    function isValidSignature(bytes32 hash, bytes calldata sig) external view returns (bytes4) {
        uint256 start = gasleft();
        while (start - gasleft() < burn) {}
        uint8 m = mode;
        if (m == 1) return 0xdeadbeef;
        if (m == 2) revert("wallet");
        if (m == 3) {
            assembly {
                for {} 1 {} {}
            }
        }
        if (m == 4) {
            (bytes32 purpose, bytes32 digest, bytes memory ecdsa) = abi.decode(sig, (bytes32, bytes32, bytes));
            (, string memory name, string memory version, uint256 chainId, address vc, bytes32 salt,) =
                IUARegistry(registry).eip712Domain();
            bytes32 ds = keccak256(
                abi.encode(
                    UAKinds.DOMAIN_TYPEHASH, keccak256(bytes(name)), keccak256(bytes(version)), chainId, vc, salt
                )
            );
            bytes32 rebuilt = UAKinds.uaAuthDigest(ds, bytes32(uint256(uint160(address(this)))), purpose, digest);
            return rebuilt == hash && ECDSA.recover(rebuilt, ecdsa) == owner ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
        }
        (address rec, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, sig);
        return err == ECDSA.RecoverError.NoError && rec == owner ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
    }
}

/// gen-1 stand-in that claims one keyHash (T-REG-4 `UAKeyInUse` across generations, which a real gen 1 cannot reach
/// once the constructor's group rule holds).
contract MockPredecessor {
    bytes32 public immutable chainUid;
    bytes32 public immutable claimedKeyHash;
    bytes32 public immutable claimedOwner;

    constructor(bytes32 chainUid_, bytes32 kh, bytes32 owner_) {
        (chainUid, claimedKeyHash, claimedOwner) = (chainUid_, kh, owner_);
    }

    function generation() external pure returns (uint8) {
        return 1;
    }

    function hederaNative() external pure returns (bool) {
        return false;
    }

    function kindEnabled(uint16) external pure returns (bool) {
        return false;
    }

    function kindOf(bytes32) external pure returns (uint16) {
        return 0;
    }

    function keyOwner(bytes32 kh) external view returns (bytes32) {
        return kh == claimedKeyHash ? claimedOwner : bytes32(0);
    }
}

abstract contract UARegistryBase is Test {
    uint64 internal constant BUDGET = 12_000_000;
    address internal constant REG_A = 0x5Ca0000000000000000000000000000000000001;
    bytes32 internal constant DIGEST = keccak256("scaas.ua.test.digest");

    bytes32 internal chainUidA;
    MockVerifier internal mock;
    UARegistry internal reg;
    bytes[8] internal keys; // kinds.json valid[0..7] = kinds 0x0100..0x0107
    uint16[7] internal KINDS = [0x0100, 0x0101, 0x0103, 0x0104, 0x0105, 0x0106, 0x0107];

    struct Member {
        uint16 kind;
        bytes32 id;
        uint16 weight;
    }

    function setUp() public virtual {
        chainUidA = vm.parseJsonBytes32(_structures(), ".contexts.A.chainUid");
        string memory j = _kindsJson();
        for (uint256 i; i < 8; ++i) {
            keys[i] = vm.parseJsonBytes(j, string.concat(".valid[", vm.toString(i), "].keyData"));
        }
        vm.chainId(31337);
        mock = new MockVerifier(0, 0);
        reg = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), true, _cfgs(address(mock)));
    }

    // ----- vectors -----

    function _kindsJson() internal view returns (string memory) {
        return vm.readFile("../vectors/ua/kinds.json");
    }

    function _structures() internal view returns (string memory) {
        return vm.readFile("../vectors/ua/structures.json");
    }

    /// kinds.json `valid[i]` holds the kinds 0x0100..0x0107 in order.
    function _key(uint16 kind) internal view returns (bytes memory) {
        return keys[kind - 0x0100];
    }

    // ----- deployment -----

    /// The gen-1 default caps (controller ruling 2026-10-12; mock verifiers stay far below them).
    function _cap(uint16 kind) internal pure returns (uint64) {
        if (kind == 0x0100 || kind == 0x0101) return 400_000;
        if (kind == 0x0105) return 70_000;
        if (kind == 0x0106) return 200_000;
        if (kind == 0x0107) return 345_000;
        return 50_000;
    }

    function _cfgs(address v) internal view returns (UARegistry.KindConfig[] memory c) {
        c = new UARegistry.KindConfig[](KINDS.length);
        for (uint256 i; i < KINDS.length; ++i) {
            c[i] = UARegistry.KindConfig(KINDS[i], v, _cap(KINDS[i]));
        }
    }

    function _deploy(
        address where,
        bytes32 uid,
        address pred,
        bool hedera,
        uint64 budget,
        address ska,
        bool msig,
        UARegistry.KindConfig[] memory cfgs
    ) internal returns (UARegistry) {
        deployCodeTo("UARegistry.sol:UARegistry", abi.encode(uid, pred, hedera, budget, ska, msig, cfgs), where);
        return UARegistry(where);
    }

    // ----- signatures -----

    function _sig(bytes memory keyData, bytes32 message) internal pure returns (bytes memory) {
        return abi.encodePacked(keccak256(abi.encode(keyData, message)));
    }

    function _pop(UARegistry r, uint16 kind, bytes memory keyData) internal view returns (bytes memory) {
        bytes32 ua = r.uaOf(kind, keyData);
        return _sig(keyData, r.uaMessage(kind, UAKinds.PURPOSE_POP, r.popDigest(ua, 0)));
    }

    function _register(UARegistry r, uint16 kind, bytes memory keyData) internal returns (bytes32) {
        return r.register(kind, keyData, _pop(r, kind, keyData), 0, "");
    }

    /// The PoP is computed first: `vm.expectRevert` applies to the next external call.
    function _registerReverts(UARegistry r, uint16 kind, bytes memory keyData, bytes memory err) internal {
        bytes memory pop = _pop(r, kind, keyData);
        vm.expectRevert(err);
        r.register(kind, keyData, pop, 0, "");
    }

    function _auth(UARegistry r, uint16 kind, bytes memory keyData, bytes32 purpose, bytes32 digest)
        internal
        view
        returns (bytes memory)
    {
        return abi.encode(keyData, _sig(keyData, r.uaMessage(kind, purpose, digest)));
    }

    function _pad(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    }

    function _ecdsa(uint256 pk, bytes32 h) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r_, bytes32 s) = vm.sign(pk, h);
        return abi.encodePacked(r_, s, v);
    }

    function _nativeSig(UARegistry r, uint256 pk, bytes32 purpose, bytes32 digest)
        internal
        view
        returns (bytes memory)
    {
        return _ecdsa(pk, r.uaAuthDigest(_pad(vm.addr(pk)), purpose, digest));
    }

    // ----- msig -----

    /// `u16 threshold ‖ u16 count ‖ count × (u16 kind ‖ bytes32 id ‖ u16 weight)`, members sorted by id here.
    function _msigKey(uint16 threshold, Member[] memory m) internal pure returns (bytes memory d) {
        for (uint256 i = 1; i < m.length; ++i) {
            for (uint256 j = i; j > 0 && m[j - 1].id > m[j].id; --j) {
                (m[j - 1], m[j]) = (m[j], m[j - 1]);
            }
        }
        d = abi.encodePacked(threshold, uint16(m.length));
        for (uint256 i; i < m.length; ++i) {
            d = abi.encodePacked(d, m[i].kind, m[i].id, m[i].weight);
        }
    }

    /// Index of member `id` in msig key data `d`.
    function _indexOf(bytes memory d, bytes32 id) internal pure returns (uint16) {
        uint256 count = uint16(bytes2(abi.encodePacked(d[2], d[3])));
        for (uint256 i; i < count; ++i) {
            bytes32 w;
            assembly ("memory-safe") {
                w := mload(add(add(d, 34), add(4, mul(36, i))))
            }
            if (w == id) return uint16(i);
        }
        revert("member");
    }

    function _memberDigest(bytes32 ua, bytes32 purpose, bytes32 digest) internal pure returns (bytes32) {
        return UAKinds.memberDigest(ua, UAKinds.uaMessage(UAKinds.MSIG, purpose, digest));
    }

    function _msigAuth(bytes memory d, UARegistry.MemberSig[] memory sigs) internal pure returns (bytes memory) {
        return abi.encode(d, abi.encode(sigs));
    }
}
```

- [ ] **Step 4: Tests T-REG / T-AUTH / T-CHAIN / T-MEMBER.** `smartcontracts/evm/test/ua/UARegistry.t.sol` (complete):

```solidity
// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {SaltedEIP712} from "../../src/common/SaltedEIP712.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UARegistryBase, MockVerifier, MockWallet, MockPredecessor} from "./UARegistryBase.sol";

/// accounts.md §1.16 T-REG / T-AUTH / T-CHAIN / T-MEMBER for the UA-2a registry, with stand-in verifiers (the real ones
/// are the verifier tasks' own tests; `UARegistryVectors.t.sol` runs the registry on signatures.json).
contract UARegistryTest is UARegistryBase {
    uint256 internal constant PK_A = 0xA11CE;
    uint256 internal constant PK_B = 0xB0B;

    // ----- surface, vectors of the identity layer -----

    function test_surface() public view {
        assertEq(reg.generation(), 1);
        assertEq(reg.predecessor(), address(0));
        assertEq(reg.chainUid(), chainUidA);
        assertEq(reg.verifyBudget(), BUDGET);
        assertFalse(reg.hederaNative());
        for (uint256 i; i < KINDS.length; ++i) {
            assertTrue(reg.kindEnabled(KINDS[i]));
            assertEq(reg.verifyCap(KINDS[i]), _cap(KINDS[i]));
        }
        assertTrue(reg.kindEnabled(UAKinds.MSIG));
        assertEq(reg.verifyCap(UAKinds.MSIG), BUDGET);
        uint16[12] memory off =
            [0x0001, 0x0002, 0x0003, 0x0102, 0x0110, 0x0111, 0x0112, 0x0113, 0x0130, 0x0133, 0x0140, 0x0142];
        for (uint256 i; i < off.length; ++i) {
            assertFalse(reg.kindEnabled(off[i]));
            assertEq(reg.verifyCap(off[i]), 0);
        }
        assertEq(reg.chainKeyHash(), UAKinds.chainKeyHash(31337));
    }

    function test_vectorsContextA() public view {
        string memory s = _structures();
        // popDigest, the UAAuth digest (gen 1) and the member digest of structures.json, context A
        bytes32 ua = vm.parseJsonBytes32(s, ".pop[0].ua");
        assertEq(reg.popDigest(ua, 0), vm.parseJsonBytes32(s, ".pop[0].popDigest"));
        bytes32 nua = vm.parseJsonBytes32(s, ".uaAuth[0].ua");
        assertEq(
            reg.uaAuthDigest(
                nua, vm.parseJsonBytes32(s, ".uaAuth[0].purposeTag"), vm.parseJsonBytes32(s, ".uaAuth[0].digest")
            ),
            vm.parseJsonBytes32(s, ".uaAuth[0].uaAuthDigest")
        );
        assertEq(
            UAKinds.memberDigest(
                vm.parseJsonBytes32(s, ".member[0].structureUa"), vm.parseJsonBytes32(s, ".member[0].uaMsg")
            ),
            vm.parseJsonBytes32(s, ".member[0].memberDigest")
        );
        string memory j = _kindsJson();
        for (uint256 i; i < KINDS.length; ++i) {
            bytes memory k = _key(KINDS[i]);
            string memory row = string.concat(".valid[", vm.toString(KINDS[i] - 0x0100), "]");
            assertEq(reg.uaOf(KINDS[i], k), vm.parseJsonBytes32(j, string.concat(row, ".ua")));
            assertEq(reg.keyHashOf(KINDS[i], k), vm.parseJsonBytes32(j, string.concat(row, ".keyHash")));
        }
    }

    // ----- T-REG -----

    function test_T_REG_1_registerEveryKind() public {
        for (uint256 i; i < KINDS.length; ++i) {
            uint16 kind = KINDS[i];
            bytes memory k = _key(kind);
            bytes32 ua = reg.uaOf(kind, k);
            vm.warp(1000 + i);
            vm.expectEmit(true, true, false, true, address(reg));
            emit IUARegistry.UARegistered(ua, kind, k, 0);
            assertEq(_register(reg, kind, k), ua);
            (IUARegistry.Record memory r, bytes32 authRef) = reg.recordOf(ua);
            assertEq(r.kind, kind);
            assertEq(r.registeredAt, 1000 + i);
            assertEq(r.keyPtr, address(0));
            assertEq(authRef, 0);
            assertEq(reg.kindOf(ua), kind);
            assertTrue(reg.isRegistered(ua));
            assertEq(reg.keyOwner(reg.keyHashOf(kind, k)), ua);
        }
        // the structure: no PoP, no keyOwner
        (bytes memory d, bytes32 ua2) = _registerMsig();
        assertEq(reg.kindOf(ua2), UAKinds.MSIG);
        assertEq(reg.keyHashOf(UAKinds.MSIG, d), 0);
    }

    /// kinds.json `invalid` rows of every kind this registry enables (msig members unregistered: the layout fails first).
    function test_T_REG_2_negativeKeyData() public {
        string memory j = _kindsJson();
        uint256 n;
        for (uint256 i; vm.keyExistsJson(j, string.concat(".invalid[", vm.toString(i), "]")); ++i) {
            string memory row = string.concat(".invalid[", vm.toString(i), "]");
            uint16 kind = uint16(vm.parseJsonUint(j, string.concat(row, ".kind")));
            if (!reg.kindEnabled(kind) || vm.parseJsonBool(j, string.concat(row, ".hederaNative"))) continue;
            bytes memory k = vm.parseJsonBytes(j, string.concat(row, ".keyData"));
            string memory reason = vm.parseJsonString(j, string.concat(row, ".reason"));
            // T-MEMBER: a hedera-native member outside a Hedera profile is UAMemberUnknown (§1.8), not UAKeyData.
            if (keccak256(bytes(reason)) == keccak256("hedera-native outside a Hedera profile")) {
                vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAMemberUnknown.selector, _firstMemberId(k)));
            } else {
                vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, kind));
            }
            reg.register(kind, k, "", 0, "");
            ++n;
        }
        assertGt(n, 50);
    }

    function test_T_REG_2_negativeRegistry() public {
        // disabled kinds: natives, out-of-scope kinds, unknown
        uint16[9] memory off = [0x0001, 0x0003, 0x0102, 0x0110, 0x0113, 0x0131, 0x0140, 0x0142, 0x0121];
        for (uint256 i; i < off.length; ++i) {
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKindDisabled.selector, off[i]));
            reg.register(off[i], hex"00", "", 0, "");
        }
        bytes memory p = _key(0x0101);
        bytes32 ua = reg.uaOf(0x0101, p);
        // wrong-tag PoP, PoP for another authRef, a PoP over the metatx purpose
        bytes memory wrongTag = _sig(p, reg.uaMessage(0x0100, UAKinds.PURPOSE_POP, reg.popDigest(ua, 0)));
        bytes memory otherAuthRef =
            _sig(p, reg.uaMessage(0x0101, UAKinds.PURPOSE_POP, reg.popDigest(ua, bytes32(uint256(1)))));
        bytes memory metatx = _sig(p, reg.uaMessage(0x0101, UAKinds.PURPOSE_METATX, reg.popDigest(ua, 0)));
        bytes[4] memory bad = [wrongTag, otherAuthRef, metatx, bytes("")];
        for (uint256 i; i < bad.length; ++i) {
            vm.expectRevert(IUARegistry.UAPoP.selector);
            reg.register(0x0101, p, bad[i], 0, "");
        }
        _register(reg, 0x0101, p);
        _registerReverts(reg, 0x0101, p, abi.encodeWithSelector(IUARegistry.UAAlreadyRegistered.selector, ua));
        // the same point under the other p256-group kind (kinds.json valid[22]: p256 key ‖ rpIdHash)
        bytes memory w = vm.parseJsonBytes(_kindsJson(), ".valid[22].keyData");
        bytes32 kh = reg.keyHashOf(0x0100, w);
        assertEq(kh, reg.keyHashOf(0x0101, p));
        _registerReverts(reg, 0x0100, w, abi.encodeWithSelector(IUARegistry.UAKeyInUse.selector, kh, ua));
        // msig: a pop is refused (structures have none)
        (bytes memory d,) = _msigMembers();
        vm.expectRevert(IUARegistry.UAPoP.selector);
        reg.register(UAKinds.MSIG, d, hex"01", 0, "");
    }

    /// Anyone may relay: two senders, one calldata ⇒ the same writes with the same values.
    function test_T_REG_3_senderIndependent() public {
        bytes memory k = _key(0x0104);
        bytes memory pop = _pop(reg, 0x0104, k);
        uint256 snap = vm.snapshotState();
        bytes32[] memory w1 = _writes(address(0xA), k, pop);
        bytes32[] memory v1 = _values(w1);
        vm.revertToState(snap);
        bytes32[] memory w2 = _writes(address(0xB), k, pop);
        assertEq(w1, w2);
        assertEq(v1, _values(w2));
    }

    function test_T_REG_3b_authRef() public {
        bytes memory k = _key(0x0103);
        bytes memory pop = _pop(reg, 0x0103, k);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAAuthRef.selector, bytes32(uint256(7))));
        reg.register(0x0103, k, pop, bytes32(uint256(7)), "");
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAAuthRef.selector, bytes32(0)));
        reg.register(0x0103, k, pop, 0, hex"00");
        (bytes memory d,) = _msigMembers();
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAAuthRef.selector, bytes32(uint256(7))));
        reg.register(UAKinds.MSIG, d, "", bytes32(uint256(7)), "");
    }

    /// Gen 2 may not enable a kind or keyHash group gen 1 enables, nor follow a registry of another chain or profile.
    function test_T_REG_4_gen2Constructor() public {
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](1);
        for (uint256 i; i < KINDS.length; ++i) {
            c[0] = UARegistry.KindConfig(KINDS[i], address(mock), 50_000);
            vm.expectRevert(abi.encodeWithSelector(UARegistry.UAConfig.selector, KINDS[i]));
            new UARegistry(chainUidA, address(reg), false, BUDGET, address(0), true, c);
        }
        vm.expectRevert(abi.encodeWithSelector(UARegistry.UAConfig.selector, uint16(0)));
        new UARegistry(
            bytes32(uint256(1)), address(reg), false, BUDGET, address(0), true, new UARegistry.KindConfig[](0)
        );
        vm.expectRevert(abi.encodeWithSelector(UARegistry.UAConfig.selector, uint16(0)));
        new UARegistry(chainUidA, address(reg), true, BUDGET, address(0), true, new UARegistry.KindConfig[](0));
        UARegistry gen2 = _gen2();
        vm.expectRevert(abi.encodeWithSelector(UARegistry.UAConfig.selector, uint16(0))); // no gen 3
        new UARegistry(chainUidA, address(gen2), false, BUDGET, address(0), true, new UARegistry.KindConfig[](0));
        assertEq(gen2.generation(), 2);
        assertEq(gen2.predecessor(), address(reg));
        (,, string memory version,,,,) = gen2.eip712Domain();
        assertEq(version, "2");
    }

    /// Gen 2 sees gen-1 records, refuses gen-1 kinds and ids, and hands gen-1 records to gen 1 for verification.
    function test_T_REG_4_gen2SeesGen1() public {
        bytes memory p = _key(0x0101);
        bytes32 p256Ua = _register(reg, 0x0101, p);
        (bytes memory d1, bytes32 msig1) = _registerMsig();
        UARegistry gen2 = _gen2();
        assertEq(gen2.kindOf(p256Ua), 0x0101);
        assertTrue(gen2.isRegistered(msig1));
        assertEq(gen2.keyOwner(reg.keyHashOf(0x0101, p)), p256Ua);
        (IUARegistry.Record memory r,) = gen2.recordOf(p256Ua);
        assertEq(r.kind, 0x0101);
        _registerReverts(gen2, 0x0101, p, abi.encodeWithSelector(IUARegistry.UAKindDisabled.selector, uint16(0x0101)));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAAlreadyRegistered.selector, msig1));
        gen2.register(UAKinds.MSIG, d1, "", 0, "");
        gen2.requireAuthorized(
            p256Ua, UAKinds.PURPOSE_METATX, DIGEST, _auth(reg, 0x0101, p, UAKinds.PURPOSE_METATX, DIGEST)
        );
        _expectUnauthorizedOn(
            gen2, p256Ua, UAKinds.PURPOSE_KEYOP, DIGEST, _auth(reg, 0x0101, p, UAKinds.PURPOSE_METATX, DIGEST)
        );
    }

    /// A gen-2 msig over a gen-1 p256 member and a gen-2 ed25519 member; gen 1 cannot register it.
    function test_T_REG_4_gen2Msig() public {
        bytes memory p = _key(0x0101);
        bytes32 p256Ua = _register(reg, 0x0101, p);
        UARegistry gen2 = _gen2();
        bytes memory ed = _key(0x0102);
        bytes32 edUa = _register(gen2, 0x0102, ed);
        Member[] memory m = new Member[](2);
        m[0] = Member(0x0101, p256Ua, 1);
        m[1] = Member(0x0102, edUa, 1);
        bytes memory d2 = _msigKey(2, m);
        bytes32 msig2 = gen2.register(UAKinds.MSIG, d2, "", 0, "");
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAMemberUnknown.selector, edUa));
        reg.register(UAKinds.MSIG, d2, "", 0, ""); // gen 1 does not know the gen-2 member
        bytes32 md = _memberDigest(msig2, UAKinds.PURPOSE_METATX, DIGEST);
        UARegistry.MemberSig[] memory s = new UARegistry.MemberSig[](2);
        uint16 ip = _indexOf(d2, p256Ua);
        uint16 ie = _indexOf(d2, edUa);
        s[ip] = UARegistry.MemberSig(ip, p, _sig(p, UAKinds.uaMessage(0x0101, UAKinds.PURPOSE_MEMBER, md)));
        s[ie] = UARegistry.MemberSig(ie, ed, _sig(ed, UAKinds.uaMessage(0x0102, UAKinds.PURPOSE_MEMBER, md)));
        gen2.requireAuthorized(msig2, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d2, s));
        s[ip].sig = _sig(p, UAKinds.uaMessage(0x0101, UAKinds.PURPOSE_METATX, md));
        _expectUnauthorizedOn(gen2, msig2, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d2, s));
    }

    /// msig re-enabled in gen 2: the same id registered in both generations is the same record.
    function test_T_REG_4_msigBothGenerations() public {
        UARegistry gen2 = _gen2();
        Member[] memory m = new Member[](1);
        m[0] = Member(UAKinds.EVM_EOA, _pad(vm.addr(PK_B)), 1);
        bytes memory d = _msigKey(1, m);
        bytes32 id = gen2.register(UAKinds.MSIG, d, "", 0, "");
        assertEq(reg.register(UAKinds.MSIG, d, "", 0, ""), id);
        (IUARegistry.Record memory ra,) = reg.recordOf(id);
        (IUARegistry.Record memory rb,) = gen2.recordOf(id);
        assertEq(abi.encode(ra), abi.encode(rb));
    }

    /// gen 2 = ed25519 (a group gen 1 does not enable) + msig.
    function _gen2() internal returns (UARegistry) {
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](1);
        c[0] = UARegistry.KindConfig(0x0102, address(mock), 50_000);
        return _deploy(address(0x5ca2), chainUidA, address(reg), false, BUDGET, address(0), true, c);
    }

    /// The code path of `UAKeyInUse` across generations (a real gen 1 cannot reach it once gen 2's group rule holds).
    function test_T_REG_4_keyInUseAcrossGenerations() public {
        bytes memory p = _key(0x0101);
        bytes32 kh = UAKinds.keyHashOf(0x0101, p);
        MockPredecessor pred = new MockPredecessor(chainUidA, kh, bytes32(uint256(0xdead) << 200));
        UARegistry gen2 =
            _deploy(address(0x5ca3), chainUidA, address(pred), false, BUDGET, address(0), false, _cfgs(address(mock)));
        _registerReverts(
            gen2,
            0x0101,
            p,
            abi.encodeWithSelector(IUARegistry.UAKeyInUse.selector, kh, bytes32(uint256(0xdead) << 200))
        );
    }

    /// Invariants: no value, records never change, `uaOf(keyData) == ua`.
    function test_T_REG_5_invariants() public {
        bytes32[] memory uas = new bytes32[](KINDS.length);
        for (uint256 i; i < KINDS.length; ++i) {
            uas[i] = _register(reg, KINDS[i], _key(KINDS[i]));
            assertEq(uas[i], UAKinds.uaOf(KINDS[i], _key(KINDS[i])));
        }
        vm.warp(block.timestamp + 1 days);
        for (uint256 i; i < KINDS.length; ++i) {
            (IUARegistry.Record memory before,) = reg.recordOf(uas[i]);
            _registerReverts(
                reg, KINDS[i], _key(KINDS[i]), abi.encodeWithSelector(IUARegistry.UAAlreadyRegistered.selector, uas[i])
            );
            (IUARegistry.Record memory after_,) = reg.recordOf(uas[i]);
            assertEq(abi.encode(before), abi.encode(after_));
        }
        vm.deal(address(this), 1 ether);
        (bool ok,) = address(reg).call{value: 1}("");
        assertFalse(ok);
        (ok,) = address(reg).call{value: 1}(abi.encodeCall(reg.register, (0x0101, hex"", hex"", 0, hex"")));
        assertFalse(ok);
        assertEq(address(reg).balance, 0);
    }

    // ----- T-AUTH -----

    function test_T_AUTH_1_kindsByPurpose() public {
        bytes32[4] memory purposes =
            [UAKinds.PURPOSE_METATX, UAKinds.PURPOSE_METATX_CANCEL, UAKinds.PURPOSE_KEYOP, UAKinds.PURPOSE_RECEIVER_FEE];
        for (uint256 i; i < KINDS.length; ++i) {
            bytes32 ua = _register(reg, KINDS[i], _key(KINDS[i]));
            for (uint256 p; p < purposes.length; ++p) {
                _kindPurpose(
                    ua, KINDS[i], KINDS[(i + 1) % KINDS.length], purposes[p], purposes[(p + 1) % purposes.length]
                );
            }
        }
        // unregistered derived id
        bytes memory e = _key(0x0102);
        _expectUnauthorized(
            UAKinds.uaOf(0x0102, e),
            UAKinds.PURPOSE_METATX,
            DIGEST,
            _auth(reg, 0x0102, e, UAKinds.PURPOSE_METATX, DIGEST)
        );
    }

    /// Passes for (kind, purpose); fails for a wrong purpose, a wrong kind's tag, another digest, other key data.
    function _kindPurpose(bytes32 ua, uint16 kind, uint16 otherKind, bytes32 purpose, bytes32 other) internal {
        bytes memory k = _key(kind);
        reg.requireAuthorized(ua, purpose, DIGEST, _auth(reg, kind, k, purpose, DIGEST));
        _expectUnauthorized(ua, purpose, DIGEST, _auth(reg, kind, k, other, DIGEST));
        _expectUnauthorized(ua, purpose, DIGEST, abi.encode(k, _sig(k, reg.uaMessage(otherKind, purpose, DIGEST))));
        _expectUnauthorized(ua, purpose, DIGEST, _auth(reg, kind, k, purpose, bytes32(0)));
        _expectUnauthorized(ua, purpose, DIGEST, _auth(reg, kind, _key(otherKind), purpose, DIGEST));
    }

    /// A Zether UA (it cannot even be registered by this generation) is never authorized.
    function test_T_AUTH_1b_zether() public {
        bytes memory y = vm.parseJsonBytes(_kindsJson(), ".valid[16].keyData");
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKindDisabled.selector, uint16(0x0140)));
        reg.register(0x0140, y, "", 0, "");
        bytes32 ua = UAKinds.uaOf(0x0140, y);
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _auth(reg, 0x0140, y, UAKinds.PURPOSE_METATX, DIGEST));
    }

    function test_T_AUTH_2_msig() public {
        (bytes memory d, bytes32 ua, Fixture memory f) = _msigRegistered();
        bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_METATX, DIGEST);
        // threshold 3: native (1) + schnorr (2) at threshold; p256 (1) + bls (1) + native (1)
        reg.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, _sigs(d, f, md, 0x9))); // native, schnorr
        reg.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, _sigs(d, f, md, 0x7))); // native, p256, bls
        // below the threshold
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, _sigs(d, f, md, 0x3)));
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, _sigs(d, f, md, 0x8)));
        // a MemberSig after the threshold
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, _sigs(d, f, md, 0xf)));
        // unsorted, duplicate index, out-of-range index
        UARegistry.MemberSig[] memory s = _sigs(d, f, md, 0x9);
        (s[0], s[1]) = (s[1], s[0]);
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, s));
        s = _sigs(d, f, md, 0x9);
        s[1] = s[0];
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, s));
        s[1].index = 4;
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, s));
        // member signatures for another purpose / another structure's digest / a wrong member key
        _expectUnauthorized(ua, UAKinds.PURPOSE_KEYOP, DIGEST, _msigAuth(d, _sigs(d, f, md, 0x9)));
        s = _sigs(d, f, _memberDigest(bytes32(uint256(1) << 200), UAKinds.PURPOSE_METATX, DIGEST), 0x9);
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, s));
        s = _sigs(d, f, md, 0x7);
        s[1].keyData = _key(0x0100);
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, s));
        // a native member's MemberSig carries no key data
        s = _sigs(d, f, md, 0x9);
        for (uint256 i; i < s.length; ++i) {
            if (s[i].keyData.length == 0) s[i].keyData = hex"01";
        }
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, s));
        // the key data in auth must be the structure's
        bytes memory d2 = bytes.concat(d);
        d2[1] = 0x02;
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d2, _sigs(d, f, md, 0x9)));
    }

    /// Native contract members: an ERC-1271 wallet (`evm-contract`) and a 7702-delegated EOA signing through its
    /// delegate's 1271 (`evm-eoa`), both over `UAAuth(memberId, member, member_digest)`.
    function test_T_AUTH_2_msigContractMembers() public {
        address session = vm.addr(PK_B);
        MockWallet wallet = new MockWallet(session, 0, 0, address(0));
        MockWallet delegate = new MockWallet(session, 0, 0, address(0));
        address eoa = vm.addr(PK_A);
        vm.signAndAttachDelegation(address(delegate), PK_A);
        Member[] memory m = new Member[](2);
        m[0] = Member(UAKinds.EVM_CONTRACT, _pad(address(wallet)), 1);
        m[1] = Member(UAKinds.EVM_EOA, _pad(eoa), 1);
        bytes memory d = _msigKey(2, m);
        bytes32 ua = reg.register(UAKinds.MSIG, d, "", 0, ""); // the delegation lands with this call
        assertEq(eoa.code.length, 23);
        bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_METATX, DIGEST);
        UARegistry.MemberSig[] memory s = new UARegistry.MemberSig[](2);
        for (uint256 i; i < 2; ++i) {
            bytes32 id = m[i].id;
            uint16 idx = _indexOf(d, id);
            s[idx] = UARegistry.MemberSig(idx, "", _ecdsa(PK_B, reg.uaAuthDigest(id, UAKinds.PURPOSE_MEMBER, md)));
        }
        reg.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, s));
        // a member signature under the structure's own purpose instead of `member` fails
        uint16 w = _indexOf(d, _pad(address(wallet)));
        s[w].sig = _ecdsa(PK_B, reg.uaAuthDigest(_pad(address(wallet)), UAKinds.PURPOSE_METATX, md));
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, s));
    }

    function test_T_AUTH_2_msigRegistration() public {
        bytes32 p256Ua = _register(reg, 0x0101, _key(0x0101));
        bytes32 eoa = _pad(vm.addr(PK_A));
        Member[] memory m = new Member[](2);
        // unregistered member
        m[0] = Member(UAKinds.EVM_EOA, eoa, 1);
        m[1] = Member(0x0103, UAKinds.uaOf(0x0103, _key(0x0103)), 1);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAMemberUnknown.selector, m[1].id));
        reg.register(UAKinds.MSIG, _msigKey(2, m), "", 0, "");
        // registered under another kind than stated
        m[1] = Member(0x0100, p256Ua, 1);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAMemberUnknown.selector, p256Ua));
        reg.register(UAKinds.MSIG, _msigKey(2, m), "", 0, "");
        // nested structure, Zether member: refused by the layout (UAKinds, kinds.json) — UAKeyData
        (, bytes32 inner) = _registerMsig();
        m[1] = Member(UAKinds.MSIG, inner, 1);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
        reg.register(UAKinds.MSIG, _msigKey(2, m), "", 0, "");
        m[1] = Member(0x0140, bytes32(uint256(1) << 200), 1);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
        reg.register(UAKinds.MSIG, _msigKey(2, m), "", 0, "");
        // duplicate member, threshold 0, threshold > weight
        m[1] = Member(UAKinds.EVM_EOA, eoa, 1);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
        reg.register(UAKinds.MSIG, _msigKey(1, m), "", 0, "");
        m[1] = Member(0x0101, p256Ua, 1);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
        reg.register(UAKinds.MSIG, _msigKey(0, m), "", 0, "");
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
        reg.register(UAKinds.MSIG, _msigKey(3, m), "", 0, "");
    }

    /// Addendum (UA-1 carry-over): `ecrecover` → address(0) never satisfies native id 0 (ua 0, or an msig member 0).
    function test_T_AUTH_3_zeroAddressNeverSigns() public {
        bytes memory garbage = abi.encodePacked(bytes32(0), bytes32(uint256(1)), uint8(27)); // ecrecover ⇒ 0
        bytes memory garbage2 = abi.encodePacked(bytes32(uint256(5)), bytes32(uint256(7)), uint8(29)); // bad v
        _expectUnauthorized(0, UAKinds.PURPOSE_METATX, DIGEST, garbage);
        _expectUnauthorized(0, UAKinds.PURPOSE_METATX, DIGEST, garbage2);
        _expectUnauthorized(0, UAKinds.PURPOSE_METATX, DIGEST, "");
        Member[] memory m = new Member[](2);
        m[0] = Member(UAKinds.EVM_EOA, bytes32(0), 1);
        m[1] = Member(UAKinds.EVM_EOA, _pad(vm.addr(PK_A)), 1);
        bytes memory d = _msigKey(1, m);
        bytes32 ua = reg.register(UAKinds.MSIG, d, "", 0, "");
        UARegistry.MemberSig[] memory s = new UARegistry.MemberSig[](1);
        s[0] = UARegistry.MemberSig(0, "", garbage);
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, s));
        s[0].sig = garbage2;
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, s));
        bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_METATX, DIGEST);
        s[0] = UARegistry.MemberSig(1, "", _nativeSig(reg, PK_A, UAKinds.PURPOSE_MEMBER, md));
        reg.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, s));
    }

    function test_T_AUTH_3_nativeEoa() public {
        bytes32 ua = _pad(vm.addr(PK_A));
        reg.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _nativeSig(reg, PK_A, UAKinds.PURPOSE_METATX, DIGEST));
        // raw digest, other purpose, other signer, high s
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _ecdsa(PK_A, DIGEST));
        _expectUnauthorized(ua, UAKinds.PURPOSE_KEYOP, DIGEST, _nativeSig(reg, PK_A, UAKinds.PURPOSE_METATX, DIGEST));
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _nativeSig(reg, PK_B, UAKinds.PURPOSE_METATX, DIGEST));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PK_A, reg.uaAuthDigest(ua, UAKinds.PURPOSE_METATX, DIGEST));
        uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes memory high = abi.encodePacked(r, bytes32(n - uint256(s)), v == 27 ? uint8(28) : uint8(27));
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, high);
    }

    function test_T_AUTH_3_native1271() public {
        address owner = vm.addr(PK_B);
        MockWallet ok = new MockWallet(owner, 0, 0, address(reg));
        bytes32 ua = _pad(address(ok));
        bytes memory sig = _ecdsa(PK_B, reg.uaAuthDigest(ua, UAKinds.PURPOSE_METATX, DIGEST));
        reg.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, sig);
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _ecdsa(PK_B, DIGEST));
        // wrong magic, revert, out of gas, over the 50 k cap
        for (uint8 mode = 1; mode <= 3; ++mode) {
            MockWallet w = new MockWallet(owner, mode, 0, address(reg));
            _expectUnauthorized(_pad(address(w)), UAKinds.PURPOSE_METATX, DIGEST, sig);
        }
        MockWallet heavy = new MockWallet(owner, 0, 60_000, address(reg));
        bytes32 hua = _pad(address(heavy));
        _expectUnauthorized(
            hua, UAKinds.PURPOSE_METATX, DIGEST, _ecdsa(PK_B, reg.uaAuthDigest(hua, UAKinds.PURPOSE_METATX, DIGEST))
        );
        // ERC-7739-style: the wallet rebuilds the hash from eip712Domain() (salt = chainUid)
        MockWallet w7739 = new MockWallet(owner, 4, 0, address(reg));
        bytes32 wua = _pad(address(w7739));
        bytes memory inner = _ecdsa(PK_B, reg.uaAuthDigest(wua, UAKinds.PURPOSE_METATX, DIGEST));
        reg.requireAuthorized(wua, UAKinds.PURPOSE_METATX, DIGEST, abi.encode(UAKinds.PURPOSE_METATX, DIGEST, inner));
        _expectUnauthorized(wua, UAKinds.PURPOSE_METATX, DIGEST, abi.encode(UAKinds.PURPOSE_KEYOP, DIGEST, inner));
    }

    /// 400 k for `SmartKeyAccount` clones (by the immutable clone codehash), 50 k for the same code elsewhere.
    function test_T_AUTH_3_smartKeyCloneCap() public {
        address owner = vm.addr(PK_B);
        MockWallet impl = new MockWallet(owner, 0, 200_000, address(0));
        UARegistry r =
            _deploy(address(0x5ca4), chainUidA, address(0), false, BUDGET, address(impl), true, _cfgs(address(mock)));
        address clone = Clones.clone(address(impl));
        bytes32 cua = _pad(clone);
        r.requireAuthorized(
            cua, UAKinds.PURPOSE_METATX, DIGEST, _ecdsa(PK_B, r.uaAuthDigest(cua, UAKinds.PURPOSE_METATX, DIGEST))
        );
        MockWallet same = new MockWallet(owner, 0, 200_000, address(0));
        bytes32 sua = _pad(address(same));
        bytes memory sig = _ecdsa(PK_B, r.uaAuthDigest(sua, UAKinds.PURPOSE_METATX, DIGEST));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, sua));
        r.requireAuthorized(sua, UAKinds.PURPOSE_METATX, DIGEST, sig);
        // a clone of the implementation on a registry without the codehash: 50 k
        _expectUnauthorized(
            cua, UAKinds.PURPOSE_METATX, DIGEST, _ecdsa(PK_B, reg.uaAuthDigest(cua, UAKinds.PURPOSE_METATX, DIGEST))
        );
    }

    /// CTR-UA-24: a 7702-delegated EOA signs with its base key, or through the delegate's 1271 within 50 k.
    function test_T_AUTH_3_eip7702() public {
        address eoa = vm.addr(PK_A);
        bytes32 ua = _pad(eoa);
        address session = vm.addr(PK_B);
        MockWallet delegate = new MockWallet(session, 0, 0, address(0));
        bytes32 h = reg.uaAuthDigest(ua, UAKinds.PURPOSE_METATX, DIGEST);
        vm.signAndAttachDelegation(address(delegate), PK_A);
        reg.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _ecdsa(PK_A, h)); // base key
        assertEq(eoa.code.length, 23);
        reg.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _ecdsa(PK_B, h)); // delegate's 1271
        _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _ecdsa(PK_A, DIGEST));
        // delegates: none (no 1271), wrong magic, reverting, out of gas, over 50 k
        address[5] memory bad = [
            address(new MockVerifier(0, 0)),
            address(new MockWallet(session, 1, 0, address(0))),
            address(new MockWallet(session, 2, 0, address(0))),
            address(new MockWallet(session, 3, 0, address(0))),
            address(new MockWallet(session, 0, 60_000, address(0)))
        ];
        for (uint256 i; i < bad.length; ++i) {
            vm.signAndAttachDelegation(bad[i], PK_A);
            _expectUnauthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _ecdsa(PK_B, h));
            reg.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, _ecdsa(PK_A, h)); // the base key stays root
        }
        // 23 bytes of code that are not a designator: a contract (1271 only, here always "invalid")
        address fake = vm.addr(PK_B);
        vm.etch(fake, abi.encodePacked(hex"63ffffffff60e01b60005260206000f3", bytes7(0)));
        assertEq(fake.code.length, 23);
        _expectUnauthorized(
            _pad(fake), UAKinds.PURPOSE_METATX, DIGEST, _nativeSig(reg, PK_B, UAKinds.PURPOSE_METATX, DIGEST)
        );
    }

    /// Every capped call fails closed: revert, short/long/wrong returndata, out of gas ⇒ UAUnauthorized; a caller
    /// that cannot hand over the full cap ⇒ UAVerifyGas, never a pass.
    function test_T_AUTH_4_failClosed() public {
        bytes memory k = _key(0x0103);
        bytes32 ua = UAKinds.uaOf(0x0103, k);
        for (uint8 mode = 1; mode <= 5; ++mode) {
            MockVerifier v = new MockVerifier(mode, 0);
            UARegistry r = _deploy(
                address(uint160(0x5cb0 + mode)),
                chainUidA,
                address(0),
                false,
                BUDGET,
                address(0),
                false,
                _cfgs(address(v))
            );
            _registerReverts(r, 0x0103, k, abi.encodePacked(IUARegistry.UAPoP.selector));
            // a record made with a good verifier at the same address, then the bad verifier swapped in
            vm.etch(address(v), address(mock).code);
            _register(r, 0x0103, k);
            vm.etch(address(v), address(new MockVerifier(mode, 0)).code);
            _expectUnauthorizedOn(
                r, ua, UAKinds.PURPOSE_METATX, DIGEST, _auth(r, 0x0103, k, UAKinds.PURPOSE_METATX, DIGEST)
            );
        }
    }

    function test_T_AUTH_4_starvation() public {
        MockVerifier slow = new MockVerifier(0, 40_000); // valid answers after 40 k gas; cap 50 k
        UARegistry r =
            _deploy(address(0x5cc0), chainUidA, address(0), false, BUDGET, address(0), false, _cfgs(address(slow)));
        bytes memory k = _key(0x0103);
        bytes32 ua = _register(r, 0x0103, k);
        bytes memory good = abi.encodeCall(
            r.requireAuthorized,
            (ua, UAKinds.PURPOSE_METATX, DIGEST, _auth(r, 0x0103, k, UAKinds.PURPOSE_METATX, DIGEST))
        );
        bytes memory bad = abi.encodeCall(
            r.requireAuthorized,
            (ua, UAKinds.PURPOSE_METATX, DIGEST, _auth(r, 0x0103, k, UAKinds.PURPOSE_KEYOP, DIGEST))
        );
        bool sawGasError;
        for (uint256 g = 10_000; g < 150_000; g += 1_000) {
            (bool okBad,) = address(r).staticcall{gas: g}(bad);
            assertFalse(okBad);
            (bool ok, bytes memory ret) = address(r).staticcall{gas: g}(good);
            if (!ok && ret.length == 4 && bytes4(ret) == UAKinds.UAVerifyGas.selector) sawGasError = true;
            if (!ok) assertTrue(ret.length == 0 || bytes4(ret) == UAKinds.UAVerifyGas.selector); // never UAUnauthorized
            if (ok) assertGe(g, 50_000);
        }
        assertTrue(sawGasError);
        // the same for an ERC-1271 wallet (cap 50 k)
        MockWallet w = new MockWallet(vm.addr(PK_B), 0, 40_000, address(0));
        bytes32 wua = _pad(address(w));
        bytes memory wsig = _ecdsa(PK_B, r.uaAuthDigest(wua, UAKinds.PURPOSE_METATX, DIGEST));
        (bool ok2, bytes memory ret2) = address(r).staticcall{gas: 45_000}(
            abi.encodeCall(r.requireAuthorized, (wua, UAKinds.PURPOSE_METATX, DIGEST, wsig))
        );
        assertFalse(ok2);
        assertEq(bytes4(ret2), UAKinds.UAVerifyGas.selector);
        r.requireAuthorized(wua, UAKinds.PURPOSE_METATX, DIGEST, wsig);
    }

    // ----- T-CHAIN, T-MEMBER -----

    /// Contexts B and C of structures.json: chain 7622 twice, same registry address, different chainUid.
    function test_T_CHAIN() public {
        string memory s = _structures();
        bytes32 uidB = vm.parseJsonBytes32(s, ".contexts.B.chainUid");
        bytes32 uidC = vm.parseJsonBytes32(s, ".contexts.C.chainUid");
        vm.chainId(7622);
        bytes memory k = _key(0x0104);
        UARegistry rC = _deploy(REG_A, uidC, address(0), false, BUDGET, address(0), true, _cfgs(address(mock)));
        bytes memory popC = _pop(rC, 0x0104, k);
        bytes32 ua = UAKinds.uaOf(0x0104, k);
        bytes32 nua = _pad(vm.addr(PK_A));
        bytes memory uaAuthC = _nativeSig(rC, PK_A, UAKinds.PURPOSE_MEMBER, DIGEST);
        _assertVectors(rC, 2, 3);
        UARegistry rB = _deploy(REG_A, uidB, address(0), false, BUDGET, address(0), true, _cfgs(address(mock)));
        _assertVectors(rB, 1, 2);
        vm.expectRevert(IUARegistry.UAPoP.selector);
        rB.register(0x0104, k, popC, 0, "");
        _expectUnauthorizedOn(rB, nua, UAKinds.PURPOSE_MEMBER, DIGEST, uaAuthC);
        rB.register(0x0104, k, _pop(rB, 0x0104, k), 0, "");
        rB.requireAuthorized(nua, UAKinds.PURPOSE_MEMBER, DIGEST, _nativeSig(rB, PK_A, UAKinds.PURPOSE_MEMBER, DIGEST));
        assertEq(rB.kindOf(ua), 0x0104);
        _assertDomain(rB, uidB);
        // chainUid 0 refused
        vm.expectRevert(SaltedEIP712.ChainUidZero.selector);
        new UARegistry(0, address(0), false, BUDGET, address(0), true, _cfgs(address(mock)));
    }

    function _assertVectors(UARegistry r, uint256 popRow, uint256 authRow) internal view {
        string memory s = _structures();
        string memory a = string.concat(".uaAuth[", vm.toString(authRow), "]");
        string memory p = string.concat(".pop[", vm.toString(popRow), "]");
        assertEq(
            r.popDigest(vm.parseJsonBytes32(s, string.concat(p, ".ua")), 0),
            vm.parseJsonBytes32(s, string.concat(p, ".popDigest"))
        );
        assertEq(
            r.uaAuthDigest(
                vm.parseJsonBytes32(s, string.concat(a, ".ua")),
                vm.parseJsonBytes32(s, string.concat(a, ".purposeTag")),
                vm.parseJsonBytes32(s, string.concat(a, ".digest"))
            ),
            vm.parseJsonBytes32(s, string.concat(a, ".uaAuthDigest"))
        );
    }

    function _assertDomain(UARegistry r, bytes32 uid) internal view {
        (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address vc,
            bytes32 salt,
            uint256[] memory ext
        ) = r.eip712Domain();
        assertEq(fields, bytes1(0x1f));
        assertEq(name, "SCaaS UARegistry");
        assertEq(version, "1");
        assertEq(chainId, block.chainid);
        assertEq(vc, address(r));
        assertEq(salt, uid);
        assertEq(ext.length, 0);
    }

    function test_T_MEMBER_hederaNative() public {
        bytes32 hedera = bytes32(uint256(0x4d2)); // long-zero 0.0.1234
        bytes32 p256Ua = _register(reg, 0x0101, _key(0x0101));
        Member[] memory m = new Member[](2);
        m[0] = Member(UAKinds.HEDERA_NATIVE, hedera, 1);
        m[1] = Member(0x0101, p256Ua, 1);
        bytes memory d = _msigKey(2, m);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAMemberUnknown.selector, hedera));
        reg.register(UAKinds.MSIG, d, "", 0, "");
        UARegistry h =
            _deploy(address(0x5ce0), chainUidA, address(0), true, BUDGET, address(0), true, _cfgs(address(mock)));
        assertTrue(h.hederaNative());
        _register(h, 0x0101, _key(0x0101));
        assertEq(h.kindOf(h.register(UAKinds.MSIG, d, "", 0, "")), UAKinds.MSIG);
    }

    // ----- constructor -----

    function test_constructorConfig() public {
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](1);
        uint16[6] memory refused = [0x0001, 0x00ff, 0x0108, 0x0110, 0x0120, 0x0130];
        for (uint256 i; i < refused.length; ++i) {
            c[0] = UARegistry.KindConfig(refused[i], address(mock), 50_000);
            vm.expectRevert(abi.encodeWithSelector(UARegistry.UAConfig.selector, refused[i]));
            new UARegistry(chainUidA, address(0), false, BUDGET, address(0), true, c);
        }
        c[0] = UARegistry.KindConfig(0x0101, address(0x1234), 50_000); // no code
        vm.expectRevert(abi.encodeWithSelector(UARegistry.UAConfig.selector, uint16(0x0101)));
        new UARegistry(chainUidA, address(0), false, BUDGET, address(0), true, c);
        c[0] = UARegistry.KindConfig(0x0101, address(mock), 0); // cap 0
        vm.expectRevert(abi.encodeWithSelector(UARegistry.UAConfig.selector, uint16(0x0101)));
        new UARegistry(chainUidA, address(0), false, BUDGET, address(0), true, c);
        c[0] = UARegistry.KindConfig(0x0101, address(mock), BUDGET + 1); // cap above the budget
        vm.expectRevert(abi.encodeWithSelector(UARegistry.UAConfig.selector, uint16(0x0101)));
        new UARegistry(chainUidA, address(0), false, BUDGET, address(0), true, c);
        UARegistry.KindConfig[] memory dup = new UARegistry.KindConfig[](2);
        dup[0] = UARegistry.KindConfig(0x0101, address(mock), 50_000);
        dup[1] = dup[0];
        vm.expectRevert(abi.encodeWithSelector(UARegistry.UAConfig.selector, uint16(0x0101)));
        new UARegistry(chainUidA, address(0), false, BUDGET, address(0), true, dup);
        vm.expectRevert(abi.encodeWithSelector(UARegistry.UAConfig.selector, uint16(0)));
        new UARegistry(chainUidA, address(0), false, 0, address(0), true, new UARegistry.KindConfig[](0));
        // msig off
        UARegistry r =
            _deploy(address(0x5cf1), chainUidA, address(0), false, BUDGET, address(0), false, _cfgs(address(mock)));
        (bytes memory d,) = _msigFixture();
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKindDisabled.selector, UAKinds.MSIG));
        r.register(UAKinds.MSIG, d, "", 0, "");
    }

    // ----- helpers -----

    struct Fixture {
        bytes32[4] ids; // native, p256, bls-bn254, schnorr-bn254
        uint16[4] kinds;
        bytes[4] keys;
    }

    /// signatures.json's structure: native EOA, p256, bls-bn254-minsig, schnorr-bn254; weights 1,1,1,2; threshold 3.
    function _msigFixture() internal view returns (bytes memory d, Fixture memory f) {
        f.kinds = [UAKinds.EVM_EOA, uint16(0x0101), uint16(0x0107), uint16(0x0104)];
        f.ids[0] = _pad(vm.addr(PK_A));
        for (uint256 i = 1; i < 4; ++i) {
            f.keys[i] = _key(f.kinds[i]);
            f.ids[i] = UAKinds.uaOf(f.kinds[i], f.keys[i]);
        }
        Member[] memory m = new Member[](4);
        for (uint256 i; i < 4; ++i) {
            m[i] = Member(f.kinds[i], f.ids[i], i == 3 ? 2 : 1);
        }
        d = _msigKey(3, m);
    }

    /// The fixture with its derived members registered (the structure itself not).
    function _msigMembers() internal returns (bytes memory d, Fixture memory f) {
        (d, f) = _msigFixture();
        for (uint256 i = 1; i < 4; ++i) {
            if (!reg.isRegistered(f.ids[i])) _register(reg, f.kinds[i], f.keys[i]);
        }
    }

    function _msigRegistered() internal returns (bytes memory d, bytes32 ua, Fixture memory f) {
        (d, f) = _msigMembers();
        ua = reg.register(UAKinds.MSIG, d, "", 0, "");
    }

    function _registerMsig() internal returns (bytes memory d, bytes32 ua) {
        (d, ua,) = _msigRegistered();
    }

    /// Member signatures of the fixture members selected by `mask` (bit i = fixture member i), in index order.
    function _sigs(bytes memory d, Fixture memory f, bytes32 md, uint256 mask)
        internal
        view
        returns (UARegistry.MemberSig[] memory s)
    {
        uint256 n;
        for (uint256 i; i < 4; ++i) {
            if (mask >> i & 1 == 1) ++n;
        }
        s = new UARegistry.MemberSig[](n);
        uint256 j;
        for (uint16 idx; idx < 4; ++idx) {
            for (uint256 i; i < 4; ++i) {
                if (mask >> i & 1 == 0 || _indexOf(d, f.ids[i]) != idx) continue;
                s[j++] = i == 0
                    ? UARegistry.MemberSig(idx, "", _nativeSig(reg, PK_A, UAKinds.PURPOSE_MEMBER, md))
                    : UARegistry.MemberSig(
                        idx, f.keys[i], _sig(f.keys[i], UAKinds.uaMessage(f.kinds[i], UAKinds.PURPOSE_MEMBER, md))
                    );
            }
        }
    }

    function _firstMemberId(bytes memory d) internal pure returns (bytes32 id) {
        assembly ("memory-safe") {
            id := mload(add(d, 38))
        }
    }

    function _expectUnauthorized(bytes32 ua, bytes32 purpose, bytes32 digest, bytes memory auth) internal {
        _expectUnauthorizedOn(reg, ua, purpose, digest, auth);
    }

    function _expectUnauthorizedOn(UARegistry r, bytes32 ua, bytes32 purpose, bytes32 digest, bytes memory auth)
        internal
    {
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
        r.requireAuthorized(ua, purpose, digest, auth);
    }

    function _writes(address sender, bytes memory k, bytes memory pop) internal returns (bytes32[] memory writes) {
        vm.record();
        vm.prank(sender);
        reg.register(0x0104, k, pop, 0, "");
        (, writes) = vm.accesses(address(reg));
    }

    function _values(bytes32[] memory slots) internal view returns (bytes32[] memory v) {
        v = new bytes32[](slots.length);
        for (uint256 i; i < slots.length; ++i) {
            v[i] = vm.load(address(reg), slots[i]);
        }
    }
}
```

- [ ] **Step 5: Build + size gate.** `/home/ha/work/ainative/scaas/scripts/capped forge build src --sizes --json > /tmp/ua2a-sizes.json; python3 ../../scripts/size_gate.py /tmp/ua2a-sizes.json size-baseline.json` (the `;` matters: `forge build --sizes` exits 1 on the three existing contracts above EIP-170, which test chains allow)
  — `size gate: 0 error(s), … contracts` (`UARegistry` runtime 18,014 B, init 23,860 B).
- [ ] **Step 6: Test.** `/home/ha/work/ainative/scaas/scripts/capped forge test --match-path test/ua/UARegistry.t.sol` —
  `Suite result: ok. 28 passed; 0 failed; 0 skipped`.
- [ ] **Step 7: Commit.**
```bash
/usr/bin/git add smartcontracts/evm/src/ua/IUARegistry.sol smartcontracts/evm/src/ua/UARegistry.sol \
  smartcontracts/evm/test/ua/UARegistryBase.sol smartcontracts/evm/test/ua/UARegistry.t.sol
/usr/bin/git commit -m "UA-2a T4: UARegistry core — records, PoP register, requireAuthorized (derived, native ECDSA/7702/1271, msig), generations, ERC-5267" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 5: UARegistry on signatures.json with the real verifiers; T-GAS

**Files:**
- Create: `smartcontracts/evm/test/ua/UARegistryVectors.t.sol`
- Create: `smartcontracts/evm/test/ua/UAGas.t.sol`

**Interfaces:**
- Consumes: Task 4; `smartcontracts/vectors/ua/signatures.json` (Task 1: `derived`, `native`, `msig` with
  `auth = abi.encode(keyData, sig)`); Task 2 `src/ua/verifiers/{P256Verifier,WebAuthnP256Verifier,Bip340Verifier}.sol`; Task 3
  `src/ua/verifiers/PairingVerifiers.sol` (`SchnorrBn254Verifier`, `SchnorrBls12381Verifier`, `BlsMinSigBls12381Verifier`,
  `BlsMinSigBn254Verifier`). Gen-1 default caps (controller ruling): webauthn-p256 400 k, p256 400 k, bip340 50 k,
  schnorr-bn254 50 k, schnorr-bls12381 70 k, bls12381-minsig 200 k, bls-bn254-minsig 345 k (in `UARegistryBase._cap`).
- Produces: the measured numbers of accounts.md §1.15 for the registry (logged with `-vv`) and the assertion that keeps
  `MSIG_MEMBER_GAS` sound.

- [ ] **Step 1: Vector integration.** Registers every derived row with its PoP at context A (registry deployed at the
  context address with `deployCodeTo` after `vm.chainId`), refuses `popOther` and every `verifyPop` negative (`UAPoP`),
  authorizes every `sigs` row, refuses every verify-side negative under the purpose whose message it carries; native
  rows on A gen 1, A gen 2 (gen 1 elsewhere, gen 2 at the context address), B; native negatives; msig sets (2 valid, 6
  invalid). `smartcontracts/evm/test/ua/UARegistryVectors.t.sol` (complete):

```solidity
// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {P256Verifier} from "../../src/ua/verifiers/P256Verifier.sol";
import {WebAuthnP256Verifier} from "../../src/ua/verifiers/WebAuthnP256Verifier.sol";
import {Bip340Verifier} from "../../src/ua/verifiers/Bip340Verifier.sol";
import {
    SchnorrBn254Verifier,
    SchnorrBls12381Verifier,
    BlsMinSigBls12381Verifier,
    BlsMinSigBn254Verifier
} from "../../src/ua/verifiers/PairingVerifiers.sol";
import {UARegistryBase} from "./UARegistryBase.sol";

/// The registry with the real UA-2a verifiers on smartcontracts/vectors/ua/signatures.json (context A, generation 1):
/// T-REG-1/T-REG-2/T-AUTH-1/T-AUTH-2/T-AUTH-3/T-CHAIN on the published rows. Gas of every call is logged (`-vv`).
contract UARegistryVectorsTest is UARegistryBase {
    string internal sj;
    bytes32 internal digest;

    function setUp() public override {
        super.setUp();
        sj = vm.readFile("../vectors/ua/signatures.json");
        digest = vm.parseJsonBytes32(sj, ".digest");
        reg = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), true, _realCfgs());
    }

    /// The gen-1 default caps (controller ruling 2026-10-12) on the real verifiers.
    function _realCfgs() internal returns (UARegistry.KindConfig[] memory c) {
        address[7] memory v = [
            address(new WebAuthnP256Verifier()),
            address(new P256Verifier()),
            address(new Bip340Verifier()),
            address(new SchnorrBn254Verifier()),
            address(new SchnorrBls12381Verifier()),
            address(new BlsMinSigBls12381Verifier()),
            address(new BlsMinSigBn254Verifier())
        ];
        c = new UARegistry.KindConfig[](7);
        for (uint256 i; i < 7; ++i) {
            c[i] = UARegistry.KindConfig(KINDS[i], v[i], _cap(KINDS[i]));
        }
    }

    function _d(uint256 i, string memory f) internal view returns (string memory) {
        return string.concat(".derived[", vm.toString(i), "].", f);
    }

    function _purposeTag(string memory p) internal pure returns (bytes32) {
        return keccak256(bytes(string.concat("scaas.ua.purpose.", p, ".v1")));
    }

    function test_vectors_derived() public {
        for (uint256 i; vm.keyExistsJson(sj, string.concat(".derived[", vm.toString(i), "]")); ++i) {
            _derivedRow(i);
        }
    }

    function _derivedRow(uint256 i) internal {
        uint16 kind = uint16(vm.parseJsonUint(sj, _d(i, "kind")));
        bytes memory k = vm.parseJsonBytes(sj, _d(i, "keyData"));
        bytes32 ua = vm.parseJsonBytes32(sj, _d(i, "ua"));
        assertEq(reg.popDigest(ua, 0), vm.parseJsonBytes32(sj, _d(i, "pop.popDigest")));
        // PoPs for another chain / registry and SIG-DST signatures offered as PoP: refused before the record exists
        _popRefused(kind, k, vm.parseJsonBytes(sj, _d(i, "popOther.sig")));
        for (uint256 n; _hasNeg(i, n); ++n) {
            if (vm.parseJsonBool(sj, _neg(i, n, "verifyPop"))) {
                _popRefused(kind, k, vm.parseJsonBytes(sj, _neg(i, n, "sig")));
            }
        }
        bytes memory pop = vm.parseJsonBytes(sj, _d(i, "pop.sig"));
        uint256 g = gasleft();
        reg.register(kind, k, pop, 0, "");
        g -= gasleft();
        emit log_named_uint(string.concat("register ", vm.parseJsonString(sj, _d(i, "name"))), g);
        assertEq(reg.kindOf(ua), kind);
        for (uint256 s; vm.keyExistsJson(sj, _d(i, string.concat("sigs[", vm.toString(s), "]"))); ++s) {
            _derivedSig(i, s, k, ua);
        }
        for (uint256 n; _hasNeg(i, n); ++n) {
            if (!vm.parseJsonBool(sj, _neg(i, n, "verifyPop"))) _derivedNegative(i, n, kind, k, ua);
        }
    }

    function _hasNeg(uint256 i, uint256 n) internal view returns (bool) {
        return vm.keyExistsJson(sj, _d(i, string.concat("negatives[", vm.toString(n), "]")));
    }

    function _neg(uint256 i, uint256 n, string memory f) internal view returns (string memory) {
        return _d(i, string.concat("negatives[", vm.toString(n), "].", f));
    }

    function _derivedSig(uint256 i, uint256 s, bytes memory k, bytes32 ua) internal {
        string memory row = string.concat("sigs[", vm.toString(s), "].");
        bytes32 p = _purposeTag(vm.parseJsonString(sj, _d(i, string.concat(row, "purpose"))));
        bytes memory auth = abi.encode(k, vm.parseJsonBytes(sj, _d(i, string.concat(row, "sig"))));
        bytes32 dg = vm.parseJsonBytes32(sj, _d(i, string.concat(row, "digest")));
        uint256 g = gasleft();
        reg.requireAuthorized(ua, p, dg, auth);
        g -= gasleft();
        if (s == 0) emit log_named_uint(string.concat("requireAuthorized ", vm.parseJsonString(sj, _d(i, "name"))), g);
    }

    /// Verify-side negatives: the registry is asked exactly the row's message under metatx or member.
    function _derivedNegative(uint256 i, uint256 n, uint16 kind, bytes memory k, bytes32 ua) internal {
        bytes32 m = vm.parseJsonBytes32(sj, _neg(i, n, "message"));
        bytes memory auth = abi.encode(k, vm.parseJsonBytes(sj, _neg(i, n, "sig")));
        bytes32 p;
        if (m == UAKinds.uaMessage(kind, UAKinds.PURPOSE_METATX, digest)) p = UAKinds.PURPOSE_METATX;
        else if (m == UAKinds.uaMessage(kind, UAKinds.PURPOSE_MEMBER, digest)) p = UAKinds.PURPOSE_MEMBER;
        else revert(string.concat(vm.parseJsonString(sj, _neg(i, n, "name")), ": a message the registry never asks"));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
        reg.requireAuthorized(ua, p, digest, auth);
    }

    function _popRefused(uint16 kind, bytes memory k, bytes memory sig) internal {
        vm.expectRevert(IUARegistry.UAPoP.selector);
        reg.register(kind, k, sig, 0, "");
    }

    function test_vectors_native() public {
        bytes32 ua = vm.parseJsonBytes32(sj, ".native.ua");
        assertEq(ua, _pad(vm.addr(vm.parseJsonUint(sj, ".native.secret"))));
        string memory s = _structures();
        // gen 1 on A, gen 2 on A (gen 1 elsewhere), gen 1 on B
        UARegistry gen1 = _deploy(
            address(0x5ca9), chainUidA, address(0), false, BUDGET, address(0), true, new UARegistry.KindConfig[](0)
        );
        for (uint256 i; vm.keyExistsJson(sj, string.concat(".native.sigs[", vm.toString(i), "]")); ++i) {
            string memory row = string.concat(".native.sigs[", vm.toString(i), "].");
            string memory ctx = vm.parseJsonString(sj, string.concat(row, "context"));
            uint256 gen = vm.parseJsonUint(sj, string.concat(row, "generation"));
            UARegistry r = reg;
            uint256 snap = vm.snapshotState();
            if (gen == 2) {
                r = _deploy(
                    REG_A, chainUidA, address(gen1), false, BUDGET, address(0), true, new UARegistry.KindConfig[](0)
                );
            } else if (keccak256(bytes(ctx)) == keccak256("B")) {
                vm.chainId(7622);
                r = _deploy(
                    REG_A,
                    vm.parseJsonBytes32(s, ".contexts.B.chainUid"),
                    address(0),
                    false,
                    BUDGET,
                    address(0),
                    true,
                    new UARegistry.KindConfig[](0)
                );
            }
            bytes32 p = _purposeTag(vm.parseJsonString(sj, string.concat(row, "purpose")));
            bytes32 dg = vm.parseJsonBytes32(sj, string.concat(row, "digest"));
            assertEq(r.uaAuthDigest(ua, p, dg), vm.parseJsonBytes32(sj, string.concat(row, "uaAuthDigest")));
            bytes memory sig = vm.parseJsonBytes(sj, string.concat(row, "sig"));
            uint256 g = gasleft();
            r.requireAuthorized(ua, p, dg, sig);
            if (i == 0) emit log_named_uint("requireAuthorized native ECDSA", g - gasleft());
            vm.revertToState(snap);
        }
        for (uint256 i; vm.keyExistsJson(sj, string.concat(".native.negatives[", vm.toString(i), "]")); ++i) {
            string memory row = string.concat(".native.negatives[", vm.toString(i), "].");
            bytes32 p = _purposeTag(vm.parseJsonString(sj, string.concat(row, "purpose")));
            bytes memory sig = vm.parseJsonBytes(sj, string.concat(row, "sig"));
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
            reg.requireAuthorized(ua, p, vm.parseJsonBytes32(sj, string.concat(row, "digest")), sig);
        }
    }

    function test_vectors_msig() public {
        // members: the derived rows' keys, registered with their PoPs
        for (uint256 i; vm.keyExistsJson(sj, string.concat(".derived[", vm.toString(i), "]")); ++i) {
            reg.register(
                uint16(vm.parseJsonUint(sj, _d(i, "kind"))),
                vm.parseJsonBytes(sj, _d(i, "keyData")),
                vm.parseJsonBytes(sj, _d(i, "pop.sig")),
                0,
                ""
            );
        }
        bytes memory d = vm.parseJsonBytes(sj, ".msig.keyData");
        uint256 g = gasleft();
        bytes32 ua = reg.register(UAKinds.MSIG, d, "", 0, "");
        emit log_named_uint("register msig (4 members)", g - gasleft());
        assertEq(ua, vm.parseJsonBytes32(sj, ".msig.ua"));
        uint256 valid;
        for (uint256 i; vm.keyExistsJson(sj, string.concat(".msig.sets[", vm.toString(i), "]")); ++i) {
            string memory row = string.concat(".msig.sets[", vm.toString(i), "].");
            bytes memory auth = vm.parseJsonBytes(sj, string.concat(row, "auth"));
            assertEq(auth, abi.encode(d, vm.parseJsonBytes(sj, string.concat(row, "sig"))));
            bytes32 p = _purposeTag(vm.parseJsonString(sj, string.concat(row, "purpose")));
            bytes32 dg = vm.parseJsonBytes32(sj, string.concat(row, "digest"));
            assertEq(_memberDigest(ua, p, dg), vm.parseJsonBytes32(sj, string.concat(row, "memberDigest")));
            if (vm.parseJsonBool(sj, string.concat(row, "valid"))) {
                g = gasleft();
                reg.requireAuthorized(ua, p, dg, auth);
                g -= gasleft();
                emit log_named_uint(
                    string.concat("requireAuthorized msig ", vm.parseJsonString(sj, string.concat(row, "name"))), g
                );
                ++valid;
            } else {
                vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
                reg.requireAuthorized(ua, p, dg, auth);
            }
        }
        assertEq(valid, 2);
    }
}
```

- [ ] **Step 2: T-GAS.** `smartcontracts/evm/test/ua/UAGas.t.sol` (complete):

```solidity
// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {BlsMinSigBn254Verifier} from "../../src/ua/verifiers/PairingVerifiers.sol";
import {UARegistryBase, MockWallet} from "./UARegistryBase.sol";

/// T-GAS (accounts.md §1.15/§1.16) for the UA-2a registry: the `msig` per-member overhead behind `MSIG_MEMBER_GAS`,
/// the structure bound, the native paths, and the gas a `register` of the heaviest kind needs. Per-kind verifier
/// gas with the real verifiers: `UARegistryVectors.t.sol` (`-vv`). Numbers are logged with `-vv`.
contract UAGasTest is UARegistryBase {
    uint256 internal constant SMART_KEY_1271_GAS = 400_000;

    /// Per-member gas of `msig` beyond the member's own verifier, for derived members verified here, derived members
    /// handed to gen 1, and native ECDSA members (mock verifiers: their own ~1–2 k is included, so it over-counts).
    /// `MSIG_MEMBER_GAS` must cover the worst of them plus what the caller must hold for the largest cap.
    function test_T_GAS_msigMemberOverhead() public {
        uint256 local = _derivedOverhead(reg, reg, 1);
        UARegistry.KindConfig[] memory none = new UARegistry.KindConfig[](0);
        UARegistry gen2 = _deploy(address(0x5ca2), chainUidA, address(reg), false, BUDGET, address(0), true, none);
        uint256 handed = _derivedOverhead(gen2, reg, 2); // other weights: other ids than gen 1's
        uint256 native = _nativeOverhead();
        emit log_named_uint("msig per derived member", local);
        emit log_named_uint("msig per gen-1 member (gen 2)", handed);
        emit log_named_uint("msig per native ECDSA member", native);
        uint256 worst = local > handed ? local : handed;
        worst = worst > native ? worst : native;
        // + two cold accounts (the member's verifier, gen 1) + what the caller holds for the largest cap
        assertLe(worst + 2 * 2_600 + SMART_KEY_1271_GAS / 63 + 5_000, 35_000, "MSIG_MEMBER_GAS");
    }

    /// msig over the 7 single-key kinds (weights 1); (gas with 7 member sigs − gas with 1) / 6.
    function _derivedOverhead(UARegistry r, UARegistry home, uint16 w) internal returns (uint256) {
        Member[] memory m = new Member[](7);
        for (uint256 i; i < 7; ++i) {
            bytes memory k = _key(KINDS[i]);
            bytes32 id = UAKinds.uaOf(KINDS[i], k);
            if (!home.isRegistered(id)) _register(home, KINDS[i], k);
            m[i] = Member(KINDS[i], id, w);
        }
        uint256[2] memory used;
        uint16[2] memory t = [uint16(1), uint16(7)];
        for (uint256 x; x < 2; ++x) {
            Member[] memory mm = new Member[](7);
            for (uint256 i; i < 7; ++i) {
                mm[i] = m[i];
            }
            bytes memory d = _msigKey(t[x] * w, mm);
            bytes32 ua = r.register(UAKinds.MSIG, d, "", 0, "");
            bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_METATX, DIGEST);
            UARegistry.MemberSig[] memory s = new UARegistry.MemberSig[](t[x]);
            for (uint16 j; j < t[x]; ++j) {
                (uint16 kind, bytes memory k) = _memberAt(d, j);
                s[j] = UARegistry.MemberSig(j, k, _sig(k, UAKinds.uaMessage(kind, UAKinds.PURPOSE_MEMBER, md)));
            }
            bytes memory auth = _msigAuth(d, s);
            uint256 g = gasleft();
            r.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, auth);
            used[x] = g - gasleft();
        }
        return (used[1] - used[0]) / 6;
    }

    function _memberAt(bytes memory d, uint16 j) internal view returns (uint16 kind, bytes memory k) {
        uint256 o = 4 + 36 * uint256(j);
        kind = uint16(bytes2(abi.encodePacked(d[o], d[o + 1])));
        k = _key(kind);
    }

    /// msig over 16 EOAs; (gas with 16 − gas with 1) / 15.
    function _nativeOverhead() internal returns (uint256) {
        uint256[2] memory used;
        uint16[2] memory t = [uint16(1), uint16(16)];
        for (uint256 x; x < 2; ++x) {
            Member[] memory m = new Member[](16);
            for (uint256 i; i < 16; ++i) {
                m[i] = Member(UAKinds.EVM_EOA, _pad(vm.addr(1000 + i)), 1);
            }
            bytes memory d = _msigKey(t[x], m);
            bytes32 ua = reg.register(UAKinds.MSIG, d, "", 0, "");
            bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_METATX, DIGEST);
            UARegistry.MemberSig[] memory s = new UARegistry.MemberSig[](t[x]);
            for (uint16 j; j < t[x]; ++j) {
                bytes32 id;
                assembly ("memory-safe") {
                    id := mload(add(add(d, 38), mul(36, j)))
                }
                uint256 pk = _pkOf(address(uint160(uint256(id))));
                s[j] = UARegistry.MemberSig(j, "", _nativeSig(reg, pk, UAKinds.PURPOSE_MEMBER, md));
            }
            bytes memory auth = _msigAuth(d, s);
            uint256 g = gasleft();
            reg.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, auth);
            used[x] = g - gasleft();
        }
        return (used[1] - used[0]) / 15;
    }

    function _pkOf(address a) internal pure returns (uint256) {
        for (uint256 pk = 1000; pk < 1016; ++pk) {
            if (vm.addr(pk) == a) return pk;
        }
        revert("pk");
    }

    /// Register step 4: Σ of the c largest caps + c × MSIG_MEMBER_GAS ≤ verifyBudget (here 1,145,000 + 105,000).
    function test_T_GAS_structureOverBudgetRefused() public {
        Member[] memory m = new Member[](3);
        uint16[3] memory kinds = [uint16(0x0100), uint16(0x0101), uint16(0x0107)];
        UARegistry tight =
            _deploy(address(0x5cc1), chainUidA, address(0), false, 1_200_000, address(0), true, _cfgs(address(mock)));
        UARegistry roomy =
            _deploy(address(0x5cc2), chainUidA, address(0), false, 1_250_000, address(0), true, _cfgs(address(mock)));
        for (uint256 i; i < 3; ++i) {
            bytes memory k = _key(kinds[i]);
            m[i] = Member(kinds[i], _register(tight, kinds[i], k), 1);
            _register(roomy, kinds[i], k);
        }
        bytes memory d = _msigKey(3, m);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
        tight.register(UAKinds.MSIG, d, "", 0, "");
        roomy.register(UAKinds.MSIG, d, "", 0, ""); // exactly at the budget
        // threshold 2 of the same three: c = 2, the two largest caps
        d = _msigKey(2, m);
        tight.register(UAKinds.MSIG, d, "", 0, "");
        // 16 native members on a chain with SmartKeyAccount clones: 16 × 435 k = 6.96 M ≤ 12 M
        UARegistry ska = _deploy(
            address(0x5cc3),
            chainUidA,
            address(0),
            false,
            BUDGET,
            address(new MockWallet(address(0), 0, 0, address(0))),
            true,
            _cfgs(address(mock))
        );
        Member[] memory n = new Member[](16);
        for (uint256 i; i < 16; ++i) {
            n[i] = Member(UAKinds.EVM_EOA, _pad(vm.addr(1000 + i)), 1);
        }
        uint256 g = gasleft();
        ska.register(UAKinds.MSIG, _msigKey(16, n), "", 0, "");
        emit log_named_uint("register msig 16 natives", g - gasleft());
        UARegistry small = _deploy(
            address(0x5cc4),
            chainUidA,
            address(0),
            false,
            6_000_000,
            address(new MockWallet(address(0), 0, 0, address(0))),
            true,
            _cfgs(address(mock))
        );
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
        small.register(UAKinds.MSIG, _msigKey(16, n), "", 0, "");
    }

    /// Caps of the gen-1 default config: ≤ verifyBudget and ≤ 50 % of it (public-chain rule, CTR-UA-23).
    function test_T_GAS_capsWithinBudget() public view {
        for (uint256 i; i < KINDS.length; ++i) {
            assertLe(reg.verifyCap(KINDS[i]), BUDGET / 2);
        }
    }

    /// Native paths: ECDSA, ERC-1271 (an ECDSA wallet), the 7702 base key.
    function test_T_GAS_native() public {
        uint256 pk = 0xA11CE;
        bytes32 ua = _pad(vm.addr(pk));
        bytes memory sig = _nativeSig(reg, pk, UAKinds.PURPOSE_METATX, DIGEST);
        uint256 g = gasleft();
        reg.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, sig);
        emit log_named_uint("requireAuthorized native ECDSA (registry warm)", g - gasleft());
        MockWallet w = new MockWallet(vm.addr(pk), 0, 0, address(0));
        bytes32 wua = _pad(address(w));
        sig = _ecdsa(pk, reg.uaAuthDigest(wua, UAKinds.PURPOSE_METATX, DIGEST));
        g = gasleft();
        reg.requireAuthorized(wua, UAKinds.PURPOSE_METATX, DIGEST, sig);
        emit log_named_uint("requireAuthorized native ERC-1271 (ECDSA wallet)", g - gasleft());
    }

    /// Addendum (b): `register(bls-bn254-minsig)` runs the G2 pairing check of `UAKinds` (needs ≥ 165,508 gas left at
    /// that point) and then the PoP under the 345 k cap (needs ≥ 355,476 left): the smallest call gas that registers.
    function test_T_GAS_registerHeadroomBlsBn254() public {
        string memory sj = vm.readFile("../vectors/ua/signatures.json");
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](1);
        c[0] = UARegistry.KindConfig(0x0107, address(new BlsMinSigBn254Verifier()), 345_000);
        UARegistry r = _deploy(REG_A, chainUidA, address(0), false, BUDGET, address(0), false, c);
        bytes memory call = abi.encodeCall(
            r.register,
            (0x0107, vm.parseJsonBytes(sj, ".derived[6].keyData"), vm.parseJsonBytes(sj, ".derived[6].pop.sig"), 0, "")
        );
        uint256 lo = 100_000;
        uint256 hi = 1_000_000;
        while (hi - lo > 500) {
            uint256 mid = (lo + hi) / 2;
            uint256 snap = vm.snapshotState();
            (bool ok,) = address(r).call{gas: mid}(call);
            vm.revertToState(snap);
            if (ok) hi = mid;
            else lo = mid;
        }
        emit log_named_uint("register bls-bn254-minsig: least call gas", hi);
        uint256 g = gasleft();
        (bool ok2,) = address(r).call(call);
        assertTrue(ok2);
        emit log_named_uint("register bls-bn254-minsig: gas used", g - gasleft());
        assertLt(hi, 500_000);
    }
}
```

- [ ] **Step 3: Test.** `/home/ha/work/ainative/scaas/scripts/capped forge test --match-path 'test/ua/UA*.t.sol' -vv` —
  `UARegistryVectorsTest 3 passed`, `UAGasTest 5 passed`, `UARegistryTest 28 passed`, `UAKindsTest 9 passed`, 0 failed;
  logs include `register bls-bn254-minsig: 272706`, `requireAuthorized p256: 16881`, `msig per gen-1 member (gen 2): 14095`,
  `register bls-bn254-minsig: least call gas: 450243` (± a few hundred gas with other verifier builds).
- [ ] **Step 4: Commit.**
```bash
/usr/bin/git add smartcontracts/evm/test/ua/UARegistryVectors.t.sol smartcontracts/evm/test/ua/UAGas.t.sol
/usr/bin/git commit -m "UA-2a T5: UARegistry on signatures.json with the real verifiers; T-GAS (msig member overhead, structure bound, headroom)" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Task 6: Docs — measured gas, vectors, rulings in the spec; TODO; roadmap

**Files:**
- Modify: `docs/contracts/accounts.md` (§1.6 `hedera-native` row, §1.8 `UAMemberUnknown` comment, §1.15 table, §1.16 vectors
  line), `TODO.md`, `docs/superpowers/plans/2026-10-12-ua-roadmap.md`

**Interfaces:**
- Consumes: Tasks 1–5 (file names, measured gas, rulings R5, R19, R20).
- Produces: the spec and project state after UA-2a.

- [ ] **Step 1: §1.15 measured numbers.** In `docs/contracts/accounts.md` §1.15 replace these table rows (match each by its
  first cell):

```markdown
| `webauthn-p256` | 96 + ~300 | 24.7 k with P256VERIFY / ~260 k Solidity (measured; invalid signatures cost the same) | ~6 k (measured) | 400 k |
| `p256` | 64 + 64 | 10.6 k with P256VERIFY / ~250 k Solidity (measured) | ~6 k (measured) | 400 k |
| `bip340` | 32 + 64 | 11.2 k osaka / 8.5 k prague (measured; one `MODEXP`) | ~6 k (measured) | 50 k |
| `schnorr-bn254` | 64 + 96 | ~29 k (measured, bounded self-call; a malformed point ~5 k) | ~6 k (measured) | 50 k |
```

  after the `musig2-bn254`, `frost-bn254` row add:

```markdown
| `schnorr-bls12381` | 128 + 160 | ~41 k (measured, bounded self-call) | ~6 k (measured) | 70 k |
| `bls-bn254-minsig` | 128 + 64 | ~125 k (measured; try-and-increment map, `CHECK_GAS` 330 k) | ~27 k (measured) | 345 k |
```

  and replace the `bls12381-minsig` row with:

```markdown
| `bls12381-minsig` | 256 + 128 | ~159 k (measured, bounded self-call) | ~6 k (measured) | 200 k |
```

  After the table's caption paragraph ("Verification per check …") add one sentence: "Measured (UA-2a, forge, osaka;
  `test/ua/UAGas.t.sol` and the verifier tests): the registry adds ~6 k per derived check; `register` costs 77 k–273 k
  per kind, and a `bls-bn254-minsig` registration needs ≥ 450 k call gas because of the 63/64 holds; `msig` adds
  `MSIG_MEMBER_GAS` = 35 k per member to the structure bound."

- [ ] **Step 2: §1.16 vectors line.** In the line starting "Cross-language vectors (`smartcontracts/vectors/ua/`;" replace
  "no signatures yet: PoP signatures and `groups.json` come with the registry's verifiers" with "`signatures.json` BUILT
  with the UA-2a verifiers (PoPs, `metatx` / `member` signatures and negatives for the seven classical kinds, native
  `UAAuth`, `msig` sets, the official BIP-340 vectors; re-verified by noble and by `scaas-ua::verify`); `groups.json` comes
  with MuSig2 / FROST (UA-2c)".

- [ ] **Step 3: §1.6 and §1.8 rulings.** In the §1.6 kind-table row of `0x0003` `hedera-native`, replace "HIP-632
  `isAuthorizedRaw` (64-byte ed25519), else as 0x0001/0x0002" with "HIP-632 `isAuthorizedRaw` (64-byte ed25519), else as
  0x0001/0x0002 (HIP-632 halts in a static frame: until a non-view path exists, `requireAuthorized` verifies it as
  0x0001/0x0002)". In the §1.8 interface, replace the comment
  `// structure member not native/registered, or kind ∉ MEMBER` with
  `// structure member not native/registered, or hedera-native outside a Hedera profile (other kinds ∉ MEMBER: UAKeyData)`.

- [ ] **Step 4: `TODO.md`.** After the `- [x] **UA-1b**` line add:

```markdown
- [~] **UA-2a** registry core + classical verifiers (owner 2026-10-12: UA-2 in three sub-plans): `UARegistry` gen 1 (`src/ua/UARegistry.sol`, `IUARegistry.sol`), verifiers `src/ua/verifiers/` (P-256, WebAuthn-P256, BIP-340, Schnorr bn254/BLS12-381, BLS min-sig BLS12-381/bn254), `signatures.json` + `scaas-ua::verify` (plan `docs/superpowers/plans/2026-10-12-ua2a-registry.md`): built on branch `ua2a-registry`, not merged. Open: HIP-632 in a view (R19). Next: UA-2b (ed25519), UA-2c (MuSig2/FROST, `groups.json`).
```

- [ ] **Step 5: Roadmap.** In `docs/superpowers/plans/2026-10-12-ua-roadmap.md` replace the UA-2 row's first cell
  "**UA-2** registry and verifiers (F1)" with "**UA-2** registry and verifiers (F1; owner 2026-10-12: three sub-plans —
  UA-2a registry core + classical verifiers, plan [2026-10-12-ua2a-registry.md](2026-10-12-ua2a-registry.md); UA-2b
  `ed25519`; UA-2c MuSig2 / FROST + `groups.json`)".

- [ ] **Step 6: Checks.** `python3 scripts/docs_check.py check` — 0 errors; `python3 scripts/docs_check.py facts check` —
  0 misses (if a fact trips on replaced wording, add a `renamed` row to `docs/history/dropped-artifacts.tsv`, as UA-1 did).

- [ ] **Step 7: Commit.**

```bash
/usr/bin/git add docs/contracts/accounts.md TODO.md docs/superpowers/plans/2026-10-12-ua-roadmap.md
/usr/bin/git commit -m "UA-2a T6: docs (measured gas, signatures.json, rulings in accounts.md), TODO, roadmap" \
  -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

### Final

- [ ] **Whole branch.** From the worktree after Task 6, in `smartcontracts/evm`: `../../scripts/capped forge test` — the
  full suite green (UA-1's 926 passed + the new UA-2a tests, 10 skipped); `FOUNDRY_EVM_VERSION=prague ../../scripts/capped
  forge test --match-path 'test/ua/verifiers/*'` green; the size gate 0 errors; in `clients/clientkeys`
  `../../scripts/capped node --test test/ua-sig.test.js` 6/6; in `clients/scaas-ua` `../../scripts/capped cargo test
  --offline` and `cargo clippy --all-targets -- -D warnings` clean; `git status` clean; docs checkers clean.
- [ ] **Review** against the Review Focus; then merge to `main` (owner). Next: UA-2b.
