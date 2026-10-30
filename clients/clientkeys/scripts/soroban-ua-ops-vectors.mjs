// Generates smartcontracts/soroban/vectors/ua-ops.json (UA-Soroban spec §10; plan SOR-D12): per UA entry of the token,
// the DEX, the router and the mandate, and per signing kind, the typed arguments (hex ScVal XDR, `auth` excluded), the
// NET-SOR-16 op digest, the registry's ua_msg and the signer's `auth`, plus the portable registrations of the signers.
// The contract tests (registered at `contracts` under `network`), the node adapter and test/soroban.test.js reproduce it.
// Keys: the S3 rows of portable.json (signatures.json's fixed secrets; pq_kat.json's seed, account 0, mldsa65 indexes 1
// and 2) and a 2-of-3 msig of ed25519, p256 and mldsa65#1. ML-DSA signs with extraEntropy: false. Test vectors only.
//   node scripts/soroban-ua-ops-vectors.mjs [--check]
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { hex, keccak_256, utf8ToBytes } from '../src/bytes.js';
import * as ua from '../src/ua.js';
import * as s from '../src/soroban.js';
import { relayRef } from '../src/metaop.js';
import { PQ_KINDS } from '../src/pq.js';
import { SCHEMES, int, secretOf, encodeMemberSigs, pqKey, pqSignMsg } from './ua-signers.mjs';

export const OUT = new URL('../../../smartcontracts/soroban/vectors/ua-ops.json', import.meta.url);
const PORTABLE = JSON.parse(readFileSync(new URL('../../../smartcontracts/vectors/ua/portable.json', import.meta.url), 'utf8'));

/** The single-key kinds of S3 (spec §3), in perKind order. */
export const SINGLE = ['webauthn-p256', 'p256', 'ed25519', 'secp256k1', 'mldsa44', 'mldsa65'];
const MEMBER = ua.purposeTag('member');
const NONE = new Uint8Array(0);

const make = (name, kind, keyData, sign) => ({ name, kind, keyData, ua: ua.deriveUA(kind, keyData), sign });
/** A single-key signer `{ name, kind, keyData, ua, sign(uaMsg) → auth }`: classical index 0 is signatures.json's secret
 *  (index i > 0: the same label with `#i`), PQ kinds pq_kat.json's seed at account 0, index i. */
function single(name, index) {
  if (PQ_KINDS[name]) {
    const kp = pqKey(name, index);
    return make(index ? `${name}#${index}` : name, PQ_KINDS[name].kind, kp.publicKey, (m) => pqSignMsg(name, kp.secretKey, m));
  }
  const sc = SCHEMES[name];
  const label = index ? `${name}#${index}` : name;
  const sk = sc.seed ? int(keccak_256(utf8ToBytes(`scaas.ua.vectors.sig.${label}`))) : secretOf(label, sc.n);
  return make(label, sc.kind, sc.keyData(sk), (m) => sc.sign(sk, m));
}
/** The 2-of-3 msig of ed25519, p256 and mldsa65#1 (weights 1, sorted by id): `sign(uaMsg)` = abi.encode(MemberSig[]) of
 *  members 0 and 1 over memberDigest(ua, uaMsg) under `member`, empty keyData (registered members, CTR-UA-33). */
function msig() {
  const members = [single('ed25519', 0), single('p256', 0), single('mldsa65', 1)]
    .sort((a, b) => (hex(a.ua) < hex(b.ua) ? -1 : 1)).map((m, index) => ({ ...m, index, weight: 1 }));
  const keyData = ua.encodeMsig(2, members.map((m) => ({ kind: m.kind, id: m.ua, weight: m.weight })));
  const id = ua.uaOf(0x0120, keyData);
  const sign = (m) => encodeMemberSigs([0, 1].map((i) => ({ index: i, keyData: NONE,
    sig: members[i].sign(ua.uaMessage(members[i].kind, MEMBER, ua.memberDigest(id, m))) })));
  return { ...make('msig-2of3', 0x0120, keyData, sign), threshold: 2, members };
}

/** The signer of `kind` (an S3 kind name or `msig`); `mldsa65` defaults to index 2 (index 1 is the msig member). */
export function signer(kind, index = kind === 'mldsa65' ? 2 : 0) {
  if (kind === 'msig') return msig();
  if (!SINGLE.includes(kind)) throw new Error(`not an S3 kind: ${kind}`);
  return single(kind, index);
}
/** `auth` for (purpose name or 32-byte tag, digest): the kind's signature over ua_msg (`pop` = the portable `pop` v2). */
export function authFor(sg, purpose, digest) {
  const tag = purpose === 'pop' ? ua.POP_V2_TAG : typeof purpose === 'string' ? ua.purposeTag(purpose) : purpose;
  const uaMsg = ua.uaMessage(sg.kind, tag, digest);
  return { uaMsg, auth: sg.sign(uaMsg) };
}

// --- the fixed network, contracts and arguments ---
const PASSPHRASE = 'Standalone Network ; February 2017';
const NET = s.networkId(PASSPHRASE);
const fill = (b) => new Uint8Array(32).fill(b);
const C = {
  registry: 'CAIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRDB3V', // 0x11 × 32
  token: 'CARCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEVQO', // 0x22 × 32 (the token cross vector's)
  mandate: 'CBKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKVLO6Q', // 0x55 × 32
  dex: 'CBTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGM2VL', // 0x66 × 32
  router: 'CBCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEJ5HZ', // 0x44 × 32
};
const TO = 'GAZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTGMZTHCM6'; // 0x33 × 32
const LANE_RELAYER = 'GCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIRCEIQAN7'; // 0x88 × 32, the order's relayer
const BUY_TOKEN = 'CB3XO53XO53XO53XO53XO53XO53XO53XO53XO53XO53XO53XO53XOJMC'; // 0x77 × 32
const VALID_UNTIL = 1_800_000_300;
const RELAY = { target: C.token, func: 'balance', args: [s.addr(TO)], salt: fill(0x5b) };
const RELAY_REF = relayRef(NET, s.addr(RELAY.target).xdr, s.vec([s.sym(RELAY.func), s.vec(RELAY.args)]).xdr, RELAY.salt);

const a = (name, type, v) => ({ name, type, v });
const ua32 = (name, sg) => a(name, 'BytesN<32>', s.bytesN(sg.ua));
const VU = a('valid_until', 'u64', s.u64(VALID_UNTIL));
const NO_RELAYER = a('relayer', 'Option<Address>', s.none());
const order = (sg) => a('order', 'Order', s.struct({
  maker: s.holderUa(sg.ua), destination: s.holderUa(sg.ua), relayer: s.addr(LANE_RELAYER), sell_token: s.addr(C.token),
  sell_amount: s.i128(1_000), buy_token: s.addr(BUY_TOKEN), buy_amount: s.i128(2_000), max_fee_ppm: s.u32(3_000),
  expiry: s.u64(VALID_UNTIL), salt: s.u64(7),
}));
const p256Ua = () => signer('p256').ua;

/** [name, contract, function, purpose, args(signer)]: the entry's arguments without `auth` (T5–T8 signatures). */
const ENTRIES = [
  ['ua_transfer', C.token, 'ua_transfer', 'metatx', (sg) => [ua32('from', sg), a('to', 'Holder', s.holderAddr(TO)),
    a('amount', 'i128', s.i128(12_345)), a('lane', 'BytesN<32>', s.bytesN(fill(0x0a))), a('nonce', 'u64', s.u64(0)), VU, NO_RELAYER]],
  ['ua_pay', C.token, 'ua_pay', 'metatx', (sg) => [ua32('from', sg), a('to', 'Holder', s.holderUa(p256Ua())),
    a('amount', 'i128', s.i128(12_345)), a('pay_ref', 'BytesN<32>', s.bytesN(fill(0x11))), VU, NO_RELAYER]],
  ['ua_pay_meta', C.token, 'ua_pay_meta', 'metatx', (sg) => [ua32('from', sg), a('to', 'Holder', s.holderAddr(TO)),
    a('amount', 'i128', s.i128(12_345)), a('salt', 'BytesN<32>', s.bytesN(fill(0x5a))),
    a('meta', 'Bytes', s.bytes(utf8ToBytes('{"invoice":"INV-0001"}'))), VU, NO_RELAYER]],
  ['ua_burn', C.token, 'ua_burn', 'metatx', (sg) => [ua32('from', sg), a('amount', 'i128', s.i128(345)),
    a('lane', 'BytesN<32>', s.bytesN(fill(0x0b))), a('nonce', 'u64', s.u64(0)), VU, NO_RELAYER]],
  ['ua_cancel_nonce', C.token, 'ua_cancel_nonce', 'metatx-cancel', (sg) => [ua32('ua', sg),
    a('lane', 'BytesN<32>', s.bytesN(fill(0x0c))), VU]],
  ['ua_order', C.token, 'ua_order', 'trade', (sg) => [a('dex', 'Address', s.addr(C.dex)), order(sg)]],
  ['ua_cancel', C.dex, 'ua_cancel', 'trade', (sg) => [order(sg)]],
  ['ua_relay', C.token, 'ua_pay', 'metatx', (sg) => [ua32('from', sg), a('to', 'Holder', s.holderAddr(C.router)),
    a('amount', 'i128', s.i128(100)), a('pay_ref', 'BytesN<32>', s.bytesN(RELAY_REF)), VU,
    a('relayer', 'Option<Address>', s.some(s.addr(C.router)))]],
  ['mtx_mandate_pay', C.mandate, 'mtx_mandate_pay', 'metatx', () => [a('token', 'Address', s.addr(C.token)),
    a('payee', 'Holder', s.holderAddr(TO)), a('amount', 'i128', s.i128(5_000)), a('pay_ref', 'BytesN<32>', s.bytesN(fill(0x12))),
    a('epoch', 'u64', s.u64(1)), VU, NO_RELAYER]],
  ['mtx_set_mandate', C.mandate, 'mtx_set_mandate', 'metatx', () => [a('token', 'Address', s.addr(C.token)),
    a('delegate', 'Holder', s.holderUa(p256Ua())), a('max_per_payment', 'i128', s.i128(50_000)),
    a('max_per_period', 'i128', s.i128(200_000)), a('period_seconds', 'u64', s.u64(86_400)), a('expiry', 'u64', s.u64(1_900_000_000)),
    a('lane', 'BytesN<32>', s.bytesN(fill(0x0d))), a('nonce', 'u64', s.u64(0)), VU, NO_RELAYER]],
];

const registrationRow = (sg) => {
  if (sg.kind !== 0x0120) {
    const r = PORTABLE.registrations.find((x) => x.name === sg.name);
    if (!r || r.keyData !== hex(sg.keyData) || r.attrs.pqzKey !== '0x' || r.attrs.kemPk !== '0x') {
      throw new Error(`portable.json has no empty-attrs row ${sg.name} of this key`);
    }
    const { name, kind, kindName, keyData, ua: id, registrationDigest, popMessage, pop } = r;
    return { name, kind, kindName, keyData, ua: id, registrationDigest, popMessage, pop };
  }
  const m = ua.holderPopMessage(sg.kind, { ua: sg.ua, keyData: sg.keyData });
  return { name: sg.name, kind: sg.kind, kindName: 'msig', keyData: hex(sg.keyData), ua: hex(sg.ua),
    threshold: sg.threshold, members: sg.members.map((x) => ({ index: x.index, kind: x.kind, id: hex(x.ua), weight: x.weight })),
    registrationDigest: hex(m.registrationDigest), popMessage: hex(m.message), memberDigest: hex(m.memberDigest), popSigners: [0, 1],
    pop: hex(sg.sign(m.message)) };
};

function build() {
  const signers = [...SINGLE, 'msig'].map((k) => signer(k));
  const registrations = [...SINGLE.slice(0, 5).map((k) => signer(k)), single('mldsa65', 1), signer('mldsa65'), signers[6]]
    .map(registrationRow);
  const entries = ENTRIES.map(([name, contract, fn, purpose, args]) => ({
    name, contract, fn, purpose, purposeTag: hex(ua.purposeTag(purpose)),
    ...(name === 'ua_relay' ? { relay: { router: C.router, target: RELAY.target, func: RELAY.func,
      args: RELAY.args.map((v) => ({ type: 'Address', xdr: hex(v.xdr) })), salt: hex(RELAY.salt), ref: hex(RELAY_REF) } } : {}),
    perKind: signers.map((sg) => {
      const list = args(sg);
      const digest = s.opDigest({ networkId: NET, contract, fn, args: list.map((x) => x.v) });
      const { uaMsg, auth } = authFor(sg, purpose, digest);
      return { kind: ua.kindInfo(sg.kind).name, ua: hex(sg.ua), args: list.map((x) => ({ name: x.name, type: x.type, xdr: hex(x.v.xdr) })),
        digest: hex(digest), uaMsg: hex(uaMsg), auth: hex(auth) };
    }),
  }));
  const note = [
    'UA-Soroban op vectors (spec §2, §10; plan SOR-D12), generated by clients/clientkeys/scripts/soroban-ua-ops-vectors.mjs.',
    'digest = sha256(xdr(Vec[Symbol("scaas_metaop_v1"), Bytes(networkId), Address(contract), Symbol(fn), Vec(args)])), args',
    'without auth, each arg a hex ScVal XDR (Option None = Void, Some(v) = v; a contracttype struct = Map of Symbol(field) sorted;',
    'a contracttype enum = Vec[Symbol(variant), payload]). uaMsg = keccak256(MSG_TAG | TAG(kind) | purposeTag | digest);',
    'auth: the kind\'s signature over uaMsg (ML-DSA over pq_msg = keccak256(TAG(kind) | uaMsg), empty context; WebAuthn the',
    'canonical abi.encode blob); msig: abi.encode(MemberSig[]) of members 0 and 1 over memberDigest(ua, uaMsg) under purpose',
    'member, empty keyData (registered members). The args name the signer (from / ua / order.maker), so args and digest are',
    'per kind. ua_order is ua_trade\'s digest (contract = token, fn "ua_order", args (dex, order)); ua_cancel the DEX\'s',
    '(SOR-D10); ua_relay the inner token.ua_pay of router.ua_relay (relayer = Some(router), pay_ref = relay.ref =',
    'keccak256("scaas.relayfee" | networkId | xdr(target) | keccak256(xdr((func, args))) | salt), open mode: to = router);',
    'mtx_* are signed by the mandate owner (mtx_set_mandate) and the delegate (mtx_mandate_pay, epoch 1 = after the',
    'first mtx_set_mandate, CTR-ACC-07). registrations[i] =',
    'register(kind, keyData, empty attrs, pop, empty pqz_pop, None) (portable, no network); the single-key rows are',
    'portable.json\'s; mldsa65 signs as mldsa65#2, mldsa65#1 is an msig member.',
  ].join(' ');
  return { note, version: 1, network: { passphrase: PASSPHRASE, networkId: hex(NET) }, contracts: C, registrations, entries };
}

/** ua-ops.json's exact text. */
export const uaOpsJson = () => `${JSON.stringify(build(), null, 2)}\n`;

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const text = uaOpsJson();
  const path = fileURLToPath(OUT);
  if (process.argv.includes('--check')) {
    let old = '';
    try { old = readFileSync(path, 'utf8'); } catch { /* missing = differs */ }
    if (old !== text) { console.error(`${path}: differs from the generator`); process.exit(1); }
    console.log(`${path}: ok`);
  } else {
    mkdirSync(fileURLToPath(new URL('.', OUT)), { recursive: true });
    writeFileSync(path, text);
    console.log(`wrote ${path}`);
  }
}
