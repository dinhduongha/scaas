// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// PqVault (spec docs/superpowers/specs/2026-11-17-pqvault.md §5.2, §5.3, §5.4, §6; CTR-PQV-03, CTR-PQV-04, CTR-PQV-17,
// CLI-PQV-09, CLI-PQV-10): the typed records in both domains (DS_V portable, DS_B chain-bound), ids, nonce scopes, stored
// blobs, the hybrid KEM wrap under PqVault's label, the passphrase key (Argon2id), K_v, sealedInfo with its sealed `prev`,
// the key usages and the SDK's key wrap (§6.10), the item keys, AAD and ciphertext. The byte formats of
// smartcontracts/vectors/pqvault/. The KEM, padding and canonical JSON are PqChat's (src/pqchat.js). UNAUDITED.
import { ml_kem1024 } from "@noble/post-quantum/ml-kem.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { argon2id } from "@noble/hashes/argon2.js";
import { gcm, gcmsiv } from "@noble/ciphers/aes.js";
import { keccak_256, sha256, concatBytes, utf8ToBytes, fromHex, abiEncode, hex } from "./bytes.js";
import { encodeType, hashStruct } from "./evm.js";
import { uaMessage, appPurpose } from "./ua.js";
import { encaps, checkKemPk, combine, pad, unpad, canonicalJson, sigHash, UASIG_ABI } from "./pqchat.js";

export { pad, unpad, canonicalJson, sigHash, UASIG_ABI };

const bytes = (v) => (v instanceof Uint8Array ? v : fromHex(v));
const tag = (s) => keccak_256(utf8ToBytes(s));
const be = (v, n) => {
  let x = BigInt(v);
  if (x < 0n || x >= 1n << BigInt(8 * n)) throw new PqVaultError(`not a uint${8 * n}`);
  const out = new Uint8Array(n);
  for (let i = n - 1; i >= 0; i--, x >>= 8n) out[i] = Number(x & 0xffn);
  return out;
};

export class PqVaultError extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

// ------------------------------------------------------------------ records (§5.2)

export const TYPE_STRINGS = Object.freeze({
  MemberKey: "MemberKey(bytes32 ua,uint64 keyId,bytes32 via)",
  Wrap: "Wrap(bytes32 member,uint64 keyId,bytes mlkemCt,bytes32 x25519Eph,bytes sealedKey)",
  PqVaultCreate:
    "PqVaultCreate(bytes32 creator,uint64 nonce,uint8 mode,bytes32 homeChain,address homeVaultContract,bytes32[] admins," +
    "MemberKey[] members,bytes32[] wrapHashes,uint16 passKdf,bytes32 passSalt,bytes sealedInfo,uint8 groupMode)" +
    "MemberKey(bytes32 ua,uint64 keyId,bytes32 via)",
  PqVaultEpoch:
    "PqVaultEpoch(bytes32 vaultId,bytes32 author,uint64 nonce,uint64 epoch,bytes32 parentEpochId,bytes32[] admins," +
    "MemberKey[] members,bytes32[] wrapHashes,uint16 passKdf,bytes32 passSalt,bytes sealedInfo)" +
    "MemberKey(bytes32 ua,uint64 keyId,bytes32 via)",
  PqVaultLeave: "PqVaultLeave(bytes32 vaultId,bytes32 epochId,bytes32 member,uint64 nonce)",
  PqVaultRemove:
    "PqVaultRemove(bytes32 vaultId,bytes32 epochId,uint64 nextEpoch,bytes32[] members,bytes32 admin,uint64 nonce)",
  PqVaultItem: "PqVaultItem(bytes32 vaultId,bytes32 epochId,bytes32 author,uint64 nonce,bytes ciphertext)",
  PqVaultEdit:
    "PqVaultEdit(bytes32 itemId,bytes32 epochId,bytes32 author,uint64 nonce,uint32 version,bytes ciphertext)",
  PqVaultBatch:
    "PqVaultBatch(bytes32 vaultId,bytes32 epochId,bytes32 author,uint64 nonce,PqVaultItem[] items)" +
    "PqVaultItem(bytes32 vaultId,bytes32 epochId,bytes32 author,uint64 nonce,bytes ciphertext)",
});
/** The seven signed records, in the order of the spec's table. */
export const SIGNED = [
  "PqVaultCreate",
  "PqVaultEpoch",
  "PqVaultLeave",
  "PqVaultRemove",
  "PqVaultItem",
  "PqVaultEdit",
  "PqVaultBatch",
];

export const TYPES = Object.freeze(
  Object.fromEntries(
    Object.entries(TYPE_STRINGS).map(([name, s]) => {
      const [, primary, list] = s.match(/^(\w+)\(([^)]*)\)/);
      if (primary !== name) throw new Error(`type string of ${name} names ${primary}`);
      return [
        name,
        list.split(",").map((f) => {
          const [type, field] = f.split(" ");
          return { name: field, type };
        }),
      ];
    }),
  ),
);
for (const name of Object.keys(TYPES)) {
  if (encodeType(TYPES, name) !== TYPE_STRINGS[name])
    throw new Error(`encodeType(${name}) differs from its type string`);
}
export const TYPEHASH = Object.freeze(Object.fromEntries(Object.entries(TYPE_STRINGS).map(([n, s]) => [n, tag(s)])));

/** `PQVAULT_APP_ID = keccak256("scaas.pqvault.v1")`, PqVault's id in the registry's open app namespace (CTR-UA-46). */
export const APP_ID_STRING = "scaas.pqvault.v1";
export const PQVAULT_APP_ID = tag(APP_ID_STRING);
/** `P_V = appPurpose(PQVAULT_APP_ID)`: what every PqVault signature is under. */
export const P_V = appPurpose(PQVAULT_APP_ID);

export const DOMAIN_NAME = "SCaaS PqVault";
export const DOMAIN_VERSION = "1";
export const DOMAIN_V_TYPE = "EIP712Domain(string name,string version,bytes32 salt)";
export const DOMAIN_B_TYPE = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
/** Mode 0: `DS_V`, no chain, no address, `salt = PQVAULT_APP_ID`. */
export const DS_V = keccak_256(
  abiEncode(
    ["bytes32", "bytes32", "bytes32", "bytes32"],
    [tag(DOMAIN_V_TYPE), tag(DOMAIN_NAME), tag(DOMAIN_VERSION), PQVAULT_APP_ID],
  ),
);
/** Mode 1: `DS_B(c)`, the chain id and the instance `c`. */
export const dsB = (chainId, contract) =>
  keccak_256(
    abiEncode(
      ["bytes32", "bytes32", "bytes32", "uint256", "address"],
      [tag(DOMAIN_B_TYPE), tag(DOMAIN_NAME), tag(DOMAIN_VERSION), chainId, contract],
    ),
  );
/** The domain of a vault of `mode` (`at` = {chainId, verifyingContract} for mode 1); any other mode is `PqVaultShape`. */
export function domainOf(mode, at) {
  if (mode === 0) return DS_V;
  if (mode === 1) return dsB(at.chainId, at.verifyingContract);
  throw new PqVaultError("PqVaultShape");
}

export const structHash = (name, s) => hashStruct(TYPES, name, s);
/** `typed(s) = keccak256(0x1901 ‖ DS ‖ hashStruct(s))`. */
export const typed = (name, s, ds) =>
  keccak_256(concatBytes(Uint8Array.of(0x19, 0x01), bytes(ds), structHash(name, s)));
/** The EIP-712 JSON of the record `name` holding `s` (its fields by name) in a vault of `mode` (`at` = {chainId,
 *  verifyingContract} for mode 1): what `ua-rs`'s PqVault path (`wallet::pqvault`) and the SDK's `sign_pqvault_record` take
 *  (owner 2026-11-22). A name outside `SIGNED` or another mode is `PqVaultShape`. */
export function typedData(name, s, mode, at) {
  if (!SIGNED.includes(name)) throw new PqVaultError("PqVaultShape");
  const str = (n) => ({ name: n, type: "string" });
  const [dt, domain] =
    mode === 0
      ? [[str("name"), str("version"), { name: "salt", type: "bytes32" }], { salt: hex(PQVAULT_APP_ID) }]
      : mode === 1
        ? [
            [
              str("name"),
              str("version"),
              { name: "chainId", type: "uint256" },
              { name: "verifyingContract", type: "address" },
            ],
            { chainId: at.chainId, verifyingContract: at.verifyingContract },
          ]
        : (() => {
            throw new PqVaultError("PqVaultShape");
          })();
  const types = { EIP712Domain: dt };
  for (const k of Object.keys(TYPES)) if (TYPE_STRINGS[name].includes(`${k}(`)) types[k] = TYPES[k];
  return { types, primaryType: name, domain: { name: DOMAIN_NAME, version: DOMAIN_VERSION, ...domain }, message: s };
}
/** What the signer signs: `uaMessage(kind, P_V, typed(s))`. */
export const signedDigest = (kind, name, s, ds) => uaMessage(kind, P_V, typed(name, s, ds));

/** §5.2 (P2): `(passKdf == 0) == (passSalt == 0)`, the contract's only check of the flag. */
export function checkPassShape(passKdf, passSalt) {
  if ((passKdf === 0) !== bytes(passSalt).every((b) => b === 0)) throw new PqVaultError("PqVaultShape");
}

// ------------------------------------------------------------------ ids and nonce scopes (§5.3)

export const TAG_STRINGS = Object.freeze(
  ["vault", "epoch", "item", "batch", "scope/vault", "scope/epoch", "scope/item"].map((t) => `scaas/pqvault/v1/${t}`),
);
const TAG = Object.fromEntries(TAG_STRINGS.map((s) => [s.slice("scaas/pqvault/v1/".length), tag(s)]));
const idOf = (t, types, values) => keccak_256(abiEncode(["bytes32", ...types], [TAG[t], ...values]));

/** Epoch 0's id too; binds the mode and the home (review r2 R5). */
export const vaultId = (creator, nonce, mode, homeChain, homeVaultContract) =>
  idOf(
    "vault",
    ["bytes32", "uint64", "uint8", "bytes32", "address"],
    [creator, nonce, mode, homeChain, homeVaultContract],
  );
export const epochId = (vault, author, nonce) =>
  idOf("epoch", ["bytes32", "bytes32", "uint64"], [vault, author, nonce]);
export const itemId = (vault, author, nonce) => idOf("item", ["bytes32", "bytes32", "uint64"], [vault, author, nonce]);
export const batchId = (vault, author, nonce) =>
  idOf("batch", ["bytes32", "bytes32", "uint64"], [vault, author, nonce]);
export const scopeVault = (creator) => idOf("scope/vault", ["bytes32"], [creator]);
/** Rekeys, leaves and removals. */
export const scopeEpoch = (vault, author) => idOf("scope/epoch", ["bytes32", "bytes32"], [vault, author]);
/** Items, edits and batches (a batch's nonce and each of its items'). */
export const scopeItem = (vault, author) => idOf("scope/item", ["bytes32", "bytes32"], [vault, author]);

// ------------------------------------------------------------------ stored blobs (§5.4)

const abiTypeOf = (t) => {
  if (t.endsWith("[]")) return `${abiTypeOf(t.slice(0, -2))}[]`;
  if (TYPES[t]) return `(${TYPES[t].map((f) => abiTypeOf(f.type)).join(",")})`;
  return t;
};
const abiValueOf = (t, v) => {
  if (t.endsWith("[]")) return v.map((x) => abiValueOf(t.slice(0, -2), x));
  if (TYPES[t]) return TYPES[t].map((f) => abiValueOf(f.type, v[f.name]));
  return v;
};
export const recordAbi = (name, s) => ({ type: abiTypeOf(name), value: abiValueOf(name, s) });
const uaSigValue = (s) => [
  s.keyData,
  s.signature,
  s.members.map((m) => [m.index, m.members.map((i) => [i.index, i.sig]), m.sig]),
];

/** Vault, epoch and remove records: `abi.encode(record, UASig)`, the full signature (VC15). */
export function groupBlob(name, s, sig) {
  const r = recordAbi(name, s);
  return abiEncode([r.type, UASIG_ABI], [r.value, uaSigValue(sig)]);
}
/** A version-1 item: `abi.encode(item, sigHash, batchId)` (`batchId` 0 for a single create). */
export function itemBlob(item, sh, batch) {
  const r = recordAbi("PqVaultItem", item);
  return abiEncode([r.type, "bytes32", "bytes32"], [r.value, sh, batch]);
}
/** An edit: `abi.encode(edit, sigHash)`. */
export function editBlob(edit, sh) {
  const r = recordAbi("PqVaultEdit", edit);
  return abiEncode([r.type, "bytes32"], [r.value, sh]);
}
/** A batch header: `abi.encode(vaultId, epochId, author, nonce, itemIds, sigHash)`. */
export const batchHeader = (b, itemIds, sh) =>
  abiEncode(
    ["bytes32", "bytes32", "bytes32", "uint64", "bytes32[]", "bytes32"],
    [b.vaultId, b.epochId, b.author, b.nonce, itemIds, sh],
  );

// ------------------------------------------------------------------ key handles and usages (§6.10)

/** `Derive` 1 (HKDF input only), `Data` 2 (`seal` / `open`), `KeyWrap` 3 (`sealKey` / `openKey`), `File` 4 (the generic file
 *  seal's key, CLI-UAL-65: a `file` item's key since C14). */
export const USAGE = Object.freeze({ Derive: 1, Data: 2, KeyWrap: 3, File: 4 });
/** The SDK's key-wrap AAD prefix: what no `seal` call can produce. */
export const KEYWRAP_LABEL = "scaas/ua/v1/keywrap";
const KEYWRAP = utf8ToBytes(KEYWRAP_LABEL);
const startsWith = (a, p) => a.length >= p.length && p.every((x, i) => a[i] === x);

/** A key and its usage, fixed when made. */
export const handle = (usage, key) => Object.freeze({ usage, key: bytes(key) });
const need = (h, usage) => {
  if (!h || h.usage !== usage) throw new PqVaultError("AppKeyUsage");
};
/** `HKDF-SHA-256(ikm = ‖ of the handles' keys, salt, info, L)`: every input a `Derive` handle; the output's usage is the caller's. */
export function derive(inputs, salt, info, length, usage) {
  for (const h of inputs) need(h, USAGE.Derive);
  return handle(usage, hkdf(sha256, concatBytes(...inputs.map((h) => h.key)), bytes(salt), bytes(info), length));
}
/** `n ‖ AES-256-GCM-SIV(key, n, pt, aad)` under a `Data` handle; an AAD led by the key-wrap label is refused. */
export function seal(h, nonce, pt, aad = new Uint8Array(0)) {
  need(h, USAGE.Data);
  if (startsWith(bytes(aad), KEYWRAP)) throw new PqVaultError("KeyWrapAad");
  return concatBytes(bytes(nonce), gcmsiv(h.key, bytes(nonce), bytes(aad)).encrypt(bytes(pt)));
}
export function open(h, blob, aad = new Uint8Array(0)) {
  need(h, USAGE.Data);
  if (startsWith(bytes(aad), KEYWRAP)) throw new PqVaultError("KeyWrapAad");
  return aeadOpen(h.key, bytes(blob), bytes(aad));
}
function aeadOpen(key, b, aad) {
  if (b.length < 28) throw new PqVaultError("AeadOpen");
  try {
    return gcmsiv(key, b.subarray(0, 12), aad).decrypt(b.subarray(12));
  } catch {
    throw new PqVaultError("AeadOpen");
  }
}
const keyWrapAad = (usage, ctx) => concatBytes(KEYWRAP, Uint8Array.of(usage), bytes(ctx));
/** `n ‖ AES-256-GCM-SIV(kw, n, inner.key, aad = "scaas/ua/v1/keywrap" ‖ u8(inner.usage) ‖ ctx)` under a `KeyWrap` handle. */
export function sealKey(kw, nonce, inner, ctx) {
  need(kw, USAGE.KeyWrap);
  return concatBytes(bytes(nonce), gcmsiv(kw.key, bytes(nonce), keyWrapAad(inner.usage, ctx)).encrypt(inner.key));
}
/** The key `sealKey` sealed, back as a handle of `usage` (bound by the AAD). */
export function openKey(kw, blob, usage, ctx) {
  need(kw, USAGE.KeyWrap);
  return handle(usage, aeadOpen(kw.key, bytes(blob), keyWrapAad(usage, ctx)));
}

// ------------------------------------------------------------------ wraps (§6.2)

const label = (s, ...parts) => concatBytes(utf8ToBytes(s), ...parts.map(bytes));
const ZERO_NONCE = new Uint8Array(12);
const EMPTY = new Uint8Array(0);

export const wrapKek = (ss, vault, epoch, member, keyId, kemPk) =>
  hkdf(
    sha256,
    ss,
    EMPTY,
    label("scaas/pqvault/v1/wrap", vault, epoch, member, be(keyId, 8), Uint8Array.of(1), keccak_256(bytes(kemPk))),
    32,
  );
const wrapAad = (vault, epoch, member, keyId) => concatBytes(bytes(vault), bytes(epoch), bytes(member), be(keyId, 8));

/** Seals `K_e` to one member (`m`, `x25519Secret`: the fixed encapsulation randomness). */
export function wrapTo({ Ke, vaultId: v, epochId: e, member, keyId, kemPk, m, x25519Secret }) {
  const enc = encaps(kemPk, m, x25519Secret);
  const kek = wrapKek(enc.ss, v, e, member, keyId, kemPk);
  const sealedKey = gcm(kek, ZERO_NONCE, wrapAad(v, e, member, keyId)).encrypt(bytes(Ke));
  return { ...enc, kek, sealedKey, wrap: { member, keyId, mlkemCt: enc.ctM, x25519Eph: enc.E, sealedKey } };
}

/** The member: `K_e` back as a `Derive` handle. */
export function openWrap({ wrap, vaultId: v, epochId: e, kemPk, dk, x25519Secret }) {
  const { pkX } = checkKemPk(kemPk);
  const ssM = ml_kem1024.decapsulate(bytes(wrap.mlkemCt), bytes(dk));
  const E = bytes(wrap.x25519Eph);
  let ssX;
  try {
    ssX = x25519.getSharedSecret(bytes(x25519Secret), E);
  } catch {
    throw new PqVaultError("all-zero X25519");
  }
  if (ssX.every((b) => b === 0)) throw new PqVaultError("all-zero X25519");
  const kek = wrapKek(combine(ssM, ssX, E, pkX), v, e, wrap.member, wrap.keyId, kemPk);
  return handle(
    USAGE.Derive,
    gcm(kek, ZERO_NONCE, wrapAad(v, e, wrap.member, wrap.keyId)).decrypt(bytes(wrap.sealedKey)),
  );
}

// ------------------------------------------------------------------ the passphrase and K_v (§6.3, §6.5)

/** `passKdf` sets (owner 2026-11-21, O8): 1 = Argon2id v0x13, 65,536 KiB, 3 passes, parallelism 4, 32 B, no secret, no data. */
export const PASS_KDF = Object.freeze({ 1: Object.freeze({ version: 0x13, m: 65536, t: 3, p: 4, dkLen: 32 }) });
/** The passphrase's bytes (Fable code review F4, controller call 2026-11-21; spec §6.3, CLI-PQV-07): RFC 8265's OpaqueString
 *  profile, applied before Argon2id: every non-ASCII space (Unicode category Zs) mapped to U+0020, then Unicode NFC, then UTF-8;
 *  an empty result or a control character (category Cc) is `PassphraseInvalid`. So one passphrase typed on two platforms, one
 *  composing and one decomposing (é, Vietnamese tone marks, Hangul), gives one `P_k`. */
export function passphraseBytes(passphrase) {
  const s = String(passphrase)
    .replace(/\p{Zs}/gu, " ")
    .normalize("NFC");
  if (s.length === 0 || /\p{Cc}/u.test(s)) throw new PqVaultError("PassphraseInvalid");
  return utf8ToBytes(s);
}

/** `P_k` as a `Derive` handle: Argon2id of `passphraseBytes(passphrase)` under `passSalt`; `null` for `passKdf` 0 (no
 *  passphrase); an unknown set is `PassKdfUnknown`. */
export function passKey(passKdf, passphrase, passSalt) {
  if (passKdf === 0) return null;
  const set = PASS_KDF[passKdf];
  if (!set) throw new PqVaultError("PassKdfUnknown");
  const salt = bytes(passSalt);
  if (salt.length !== 32 || salt.every((b) => b === 0)) throw new PqVaultError("PqVaultShape");
  return handle(USAGE.Derive, argon2id(passphraseBytes(passphrase), salt, { ...set, maxmem: 2 ** 31 }));
}
/** `K_v = HKDF(K_e ‖ P_k, "scaas/pqvault/v1/vkey" ‖ vaultId ‖ epochId ‖ be16(passKdf))`, `P_k` empty for `passKdf` 0. */
export const vaultKey = (Ke, Pk, vault, epoch, passKdf) =>
  derive(Pk ? [Ke, Pk] : [Ke], EMPTY, label("scaas/pqvault/v1/vkey", vault, epoch, be(passKdf, 2)), 32, USAGE.Derive);

// ------------------------------------------------------------------ sealedInfo and prev (§6.4)

export const infoKey = (Kv, vault, epoch) =>
  derive([Kv], EMPTY, label("scaas/pqvault/v1/info", vault, epoch), 32, USAGE.Data);
export const prevKey = (Kv, vault, epoch, prevEpoch) =>
  derive([Kv], EMPTY, label("scaas/pqvault/v1/prev", vault, epoch, prevEpoch), 32, USAGE.KeyWrap);
const prevCtx = (vault, epoch, prevEpoch) => concatBytes(bytes(vault), bytes(epoch), bytes(prevEpoch));
/** `keyWrap = n ‖ AES-256-GCM-SIV(kPrev, n, K_v(prev), "scaas/ua/v1/keywrap" ‖ u8(Derive) ‖ vaultId ‖ epochId ‖ prevEpochId)`, 60 B. */
export const keyWrap = (Kv, vault, epoch, prevEpoch, KvPrev, nonce) =>
  sealKey(prevKey(Kv, vault, epoch, prevEpoch), nonce, KvPrev, prevCtx(vault, epoch, prevEpoch));
/** The earlier `K_v`, a `Derive` handle. */
export const openPrev = (Kv, vault, epoch, prevEpoch, kw) =>
  openKey(prevKey(Kv, vault, epoch, prevEpoch), kw, USAGE.Derive, prevCtx(vault, epoch, prevEpoch));

/** `sealedInfo`'s plaintext (Fable code review F12, owner 2026-11-21): `u32be(len) ‖ content ‖ zeros` to 1,024 B, the
 *  smallest bucket (so the size does not show whether the epoch links `prev`, nor a longer name), else to the next power of two,
 *  at most 16,384 B. Each byte is state gas: 1,024 B sealed is 1,052 B. */
export function padInfo(content) {
  const c = bytes(content);
  if (c.length + 4 > 16384) throw new PqVaultError("SealedInfoLength");
  let n = 1024;
  while (n < c.length + 4) n *= 2;
  return padTo(c, n);
}
/** The content of a `padInfo` plaintext; anything `padInfo` would not write is `Padding`. */
export function unpadInfo(pt) {
  const p = bytes(pt);
  const n = p.length >= 4 ? new DataView(p.buffer, p.byteOffset).getUint32(0) : -1;
  const c = n >= 0 && n <= p.length - 4 ? p.slice(4, 4 + n) : null;
  if (!c || c.length + 4 > 16384) throw new PqVaultError("Padding");
  const q = padInfo(c);
  if (q.length !== p.length || !q.every((x, i) => x === p[i])) throw new PqVaultError("Padding");
  return c;
}
const padTo = (c, n) => {
  const out = new Uint8Array(n);
  out.set(be(c.length, 4));
  out.set(c, 4);
  return out;
};

/** `sealedInfo = n ‖ AES-256-GCM-SIV(kInfo, n, padInfo(canonical JSON))`, empty AAD: 1,052 to 16,412 B. */
export function sealInfo(Kv, vault, epoch, info, nonce) {
  const json = canonicalJson(info);
  const pt = padInfo(utf8ToBytes(json));
  const kInfo = infoKey(Kv, vault, epoch);
  return { json, pt, kInfo: kInfo.key, sealedInfo: seal(kInfo, nonce, pt) };
}
/** Opens `sealedInfo`; a failed tag is `PassphraseWrong` from the caller's view when the wrap opened (§6.5). */
export function openInfo(Kv, vault, epoch, sealed) {
  let pt;
  try {
    pt = open(infoKey(Kv, vault, epoch), sealed);
  } catch {
    throw new PqVaultError("PassphraseWrong");
  }
  return JSON.parse(new TextDecoder().decode(unpadInfo(pt)));
}
/** A reader's walk back (VC7): the key `prev` carries must open the `sealedInfo` of the epoch it names, else `PrevKeyWrong`. */
export function checkPrev(KvPrev, vault, prevEpoch, prevSealedInfo) {
  try {
    return openInfo(KvPrev, vault, prevEpoch, prevSealedInfo);
  } catch {
    throw new PqVaultError("PrevKeyWrong");
  }
}

// ------------------------------------------------------------------ files (§6.8)

export const fileKey = (Kv, vault, epoch, item, version) =>
  derive([Kv], EMPTY, label("scaas/pqvault/v1/file", vault, epoch, item, be(version, 4)), 32, USAGE.KeyWrap);
/** The file key's `sealKey` context: `vaultId ‖ epochId ‖ itemId ‖ be32(version)`, `kFile`'s own inputs. */
export const fileCtx = (vault, epoch, item, version) =>
  concatBytes(bytes(vault), bytes(epoch), bytes(item), be(version, 4));

// ------------------------------------------------------------------ items (§6.4, §6.6)

export const CT_MIN = 32;
export const CT_MAX = 16416;
/** `okm = HKDF(K_v, salt r, "scaas/pqvault/v1/item" ‖ vaultId ‖ epochId ‖ itemId ‖ be32(version) ‖ author, 44)`; bk = okm[0:32]
 *  (`Data`), n = okm[32:44]. */
export function itemKeys(Kv, r, x) {
  need(Kv, USAGE.Derive);
  const okm = hkdf(
    sha256,
    Kv.key,
    bytes(r),
    label("scaas/pqvault/v1/item", x.vaultId, x.epochId, x.itemId, be(x.version, 4), x.author),
    44,
  );
  return { okm, bk: handle(USAGE.Data, okm.subarray(0, 32)), n: okm.subarray(32, 44) };
}
/** `abi.encode(vaultId, epochId, itemId, uint32 version, author, homeChain, homeVaultContract)`, 224 B. */
export const itemAad = (x) =>
  abiEncode(
    ["bytes32", "bytes32", "bytes32", "uint32", "bytes32", "bytes32", "address"],
    [x.vaultId, x.epochId, x.itemId, x.version, x.author, x.homeChain, x.homeVaultContract],
  );
/** At most the 16,384 B bucket per version (VC9). */
export function padItem(content) {
  const c = bytes(content);
  if (c.length + 4 > 16384) throw new PqVaultError("CiphertextLength");
  return pad(c);
}
/** `ciphertext = r ‖ AES-256-GCM-SIV(bk, n, pt, aad)` of a padded plaintext `pt`. */
export function encryptItem(Kv, r, x, pt) {
  const { bk, n } = itemKeys(Kv, r, x);
  return concatBytes(bytes(r), gcmsiv(bk.key, n, itemAad(x)).encrypt(bytes(pt)));
}
/** The item's JSON value; refuses the length, the tag (`AeadOpen`), the padding (`padding`). */
export function decryptItem(Kv, x, ciphertext) {
  const c = bytes(ciphertext);
  if (c.length < CT_MIN || c.length > CT_MAX) throw new PqVaultError("CiphertextLength");
  const { bk, n } = itemKeys(Kv, c.subarray(0, 16), x);
  let pt;
  try {
    pt = gcmsiv(bk.key, n, itemAad(x)).decrypt(c.subarray(16));
  } catch {
    throw new PqVaultError("AeadOpen");
  }
  let content;
  try {
    content = unpad(pt);
  } catch {
    throw new PqVaultError("Padding");
  }
  return JSON.parse(new TextDecoder().decode(content));
}
