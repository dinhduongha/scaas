// typed-signing C1: what an entry's calldata must hold, in order, written from Appendix X.3 + the C0 findings and from the row's
// own `types` and `message`, with no code of src/: test/typed-ops.test.js (its own decoder) and scripts/typed-ops-cast-check.mjs
// (`cast`) compare decoded calldata with this, so a swapped parameter cannot pass as a round trip.
const G = (p) => [p.x0, p.x1, p.y0, p.y1];
const pqzArgsSingle = (t) => [t.p, t.validUntilBlock, t.shieldIn, t.fromUA, t.toUA, t.beneficiaryUA, t.salt, t.u, t.vTo, t.vFrom, t.vAuditor, t.sealedMemo];
const pqzArgsMulti = (t) => [t.p, t.validUntilBlock, t.shieldIn, t.fromUA, t.beneficiaryUA, t.decoyFee, t.salt, t.u,
  t.legs.map((l) => [l.ua, l.v, l.vAuditor]), t.vFrom, t.sealedMemo];
const pqzBurn = (t) => [t.p, t.validUntilBlock, t.shieldIn, t.fromUA, t.beneficiaryUA, t.u, t.vFrom];
const zSingle = (t) => [t.accSeq, t.sendCounter, t.validUntilBlock, t.salt, t.beneficiaryUA, G(t.yFrom), G(t.yTo), G(t.cOut), G(t.dOut), G(t.cDeb), G(t.cAud)];
const zMulti = (t) => [t.accSeq, t.sendCounter, t.validUntilBlock, t.salt, t.beneficiaryUA, t.decoyFee, G(t.yFrom), G(t.dOut), G(t.cDeb),
  t.legs.map((l) => [G(l.yTo), G(l.cOut), G(l.cAud), G(l.dAud)]), t.sealedMemo];
const zBurn = (t) => [t.accSeq, t.sendCounter, t.validUntilBlock, t.beneficiaryUA, G(t.yFrom)];
const uw = (u) => [u.underlying, u.recipient, u.amount, u.minOut];
const uaTuple = (s) => [s.keyData, s.signature, s.members.map((x) => [x.index, x.members.map((y) => [y.index, y.sig]), x.sig])];
const CONF = {
  PqzTransferSingle: (m, x) => [pqzArgsSingle(m.args), m.proof, uaTuple(x.pqzAuth), m.accHint],
  PqzTransferSingleCompact: (m, x) => [pqzArgsSingle(m.args), m.proof, uaTuple(x.pqzAuth), m.accHint],
  PqzTransfer: (m, x) => [pqzArgsMulti(m.args), m.proof, uaTuple(x.pqzAuth), m.accHint],
  PqzTransferCompact: (m, x) => [pqzArgsMulti(m.args), m.proof, uaTuple(x.pqzAuth), m.accHint],
  PqzUnshield: (m, x) => [pqzBurn(m.args), [m.amount, m.recipient], m.proof, uaTuple(x.pqzAuth), m.accHint],
  PqzUnshieldUnwrap: (m, x) => [pqzBurn(m.args), uw(m.unwrap), m.proof, uaTuple(x.pqzAuth), m.accHint],
  ZetherTransferSingle: (m) => [zSingle(m.args), m.proof],
  ZetherTransfer: (m) => [zMulti(m.args), m.proof],
  ZetherTransferCompact: (m) => [zMulti(m.args), m.proof],
  ZetherUnshield: (m) => [zBurn(m.args), m.amount, m.recipient, m.proof],
  ZetherUnshieldUnwrap: (m) => [zBurn(m.args), uw(m.unwrap), m.proof],
  RollOverSigned: (m, x) => [m.ua, m.expectedPendingSeq, m.validUntilBlock, uaTuple(x.ownerSig)],
  SetRollOverMode: (m, x) => [m.ua, m.rollOverMode, m.validUntilBlock, uaTuple(x.ownerSig)],
};
const envelope = (m) => [m.from, m.batch, m.nonce, m.validUntil, m.mode, m.relayer, m.fee, m.feeRecipient];
const tradeTuple = (o) => [o.from, o.receiveToken, o.amount, o.receiveAmount, o.minFill, o.fee, o.relayer, o.dex, o.destination,
  o.flags, o.batch, o.nonce, o.validUntil];
const wrapTuple = (o) => [o.from, o.wrappedToken, o.amount, o.minMinted, o.minFill, o.fee, o.relayer, o.destination, o.flags,
  o.batch, o.nonce, o.validUntil];
const asTrade = (o) => ({ ...o, receiveToken: o.wrappedToken, receiveAmount: o.minMinted, dex: o.wrappedToken });
const transferTuple = (t) => [t.from, t.to, t.value, t.entryRef, t.batch, t.nonce, t.validUntil, t.mode, t.relayer, t.fee, t.feeRecipient];
const OTHER = {
  ReceiverFee: (m, s, d) => [transferTuple(m.payment), d.extra.payerSig, m.fee, m.feeRecipient, m.validUntil, s],
  UAReceiverFee: (m, s, d) => [transferTuple(m.payment), ['0x', d.extra.payerSig, []], m.fee, m.feeRecipient, m.validUntil, ['0x', s, []]],
  RelayFee: (m, s) => [m.from, m.target, m.callDataHash, m.payee, m.value, m.validUntil, s],
  UARelayFee: (m, s) => [m.from, m.target, m.callDataHash, m.payee, m.value, m.validUntil, ['0x', s, []]],
  WrapOrder: (m, s, d) => [d.domain.verifyingContract, wrapTuple(m), s],
  UAWrapOrder: (m, s, d) => [d.domain.verifyingContract, wrapTuple(m), ['0x', s, []]],
  CancelOrder: (m, s) => [tradeTuple(m.order), s],
  CancelUAOrder: (m, s) => [tradeTuple(m.order), ['0x', s, []]],
  CancelWrapOrder: (m, s) => [tradeTuple(asTrade(m.order)), s],
  CancelUAWrapOrder: (m, s) => [tradeTuple(asTrade(m.order)), ['0x', s, []]],
  CancelDexOrder: (m, s) => [[[m.order.sellToken, tradeTuple(m.order.order)]], [s]],
  UACancelNonce: (m, s) => [m.ua, m.batch, m.validUntil, ['0x', s, []]],
  ZetherRollOver: (m, s) => [m.ua, m.expectedPendingSeq, m.validUntilBlock, ['0x', s, []]],
  ZetherSetRollOverMode: (m, s) => [m.ua, m.mode, m.validUntilBlock, ['0x', s, []]],
};
const ACCOUNT = new Set(['AddKey', 'RemoveKey', 'RotateKey', 'SetGuardian', 'CancelRecovery']);

/** The entry's parameters, in order, from the row alone: `abi.decode` of the row's calldata must equal this. */
export function expectedCall(name, r, d) {
  const m = r.message;
  if (OTHER[name]) return OTHER[name](m, d.signature, d);
  const base = name.replace(/^UA/, '');
  const ua = name !== base;
  const own = CONF[base] ? CONF[base](m, d.extra) : r.types[name].slice(1, -7).map((f) => m[f.name]);
  const account = ACCOUNT.has(name) || (name === 'Execute' && d.domain.name === 'SCaaS SmartKeyAccount');
  const sig = account ? ['0', [], d.signature] : ua && name !== 'UAShield' ? ['0x', d.signature, []] : d.signature;
  return [envelope(m), ...own, sig];
}

/** Decoded values and `expectedCall` on one form: lower-case hex, decimal strings. */
export const norm = (v) => (Array.isArray(v) ? v.map(norm) : typeof v === 'string' ? v.toLowerCase() : String(v));
