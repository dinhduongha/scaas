// typed-signing C1: what an entry's calldata must hold, in order, written from Appendix X.3 + the C0 findings and from the row's
// own `types` and `message`, with no code of src/: test/typed-ops.test.js (its own decoder) and scripts/typed-ops-cast-check.mjs
// (`cast`) compare decoded calldata with this, so a swapped parameter cannot pass as a round trip. Group 3h: the PQZ args' `ownTag`.
const G = (p) => [p.x0, p.x1, p.y0, p.y1];
const pqzArgsSingle = (t) => [t.p, t.validUntilBlock, t.shieldIn, t.fromUA, t.keyVersion, t.toUA, t.beneficiaryUA, t.salt, t.ownTag, t.u, t.vTo, t.vFrom, t.vAuditor, t.sealedMemo];
const pqzArgsMulti = (t) => [t.p, t.validUntilBlock, t.shieldIn, t.fromUA, t.keyVersion, t.beneficiaryUA, t.decoyFee, t.salt, t.ownTag, t.u,
  t.legs.map((l) => [l.ua, l.v, l.vAuditor]), t.vFrom, t.sealedMemo];
const pqzBurn = (t) => [t.p, t.validUntilBlock, t.shieldIn, t.fromUA, t.keyVersion, t.beneficiaryUA, t.ownTag, t.u, t.vFrom];
const zSingle = (t) => [t.accSeq, t.sendCounter, t.validUntilBlock, t.salt, t.beneficiaryUA, G(t.yFrom), G(t.yTo), G(t.cOut), G(t.dOut), G(t.cDeb), G(t.cAud)];
const zMulti = (t) => [t.accSeq, t.sendCounter, t.validUntilBlock, t.salt, t.beneficiaryUA, t.decoyFee, G(t.yFrom), G(t.dOut), G(t.cDeb),
  t.legs.map((l) => [G(l.yTo), G(l.cOut), G(l.cAud), G(l.dAud)]), t.sealedMemo];
const zBurn = (t) => [t.accSeq, t.sendCounter, t.validUntilBlock, t.beneficiaryUA, G(t.yFrom)];
const envTuple = (e) => [e.registry, e.smartKeyAccountImpl, e.hedera, e.deps, e.params, e.libs, e.libCodeHashes];
const uw = (u) => [u.underlying, u.recipient, u.amount, u.minOut];
const uaTuple = (s) => [s.keyData, s.signature, s.members.map((x) => [x.index, x.members.map((y) => [y.index, y.sig]), x.sig])];
// group 3f (PQZ verifier mode spec §5.3): `PqzSignedVerdict {PqzVerdict pqzVerdict; UASig sig}`, after the signature of the six
// PQZ entries
const VERDICT = new Set(['PqzTransferSingle', 'PqzTransferSingleCompact', 'PqzTransfer', 'PqzTransferCompact', 'PqzUnshield', 'PqzUnshieldUnwrap']);
const verdictTuple = ({ pqzVerdict: v, sig }) => [[v.token, v.chainId, v.proofSystemId, v.statementHash, v.proofHash, v.pqzVerifierEpoch,
  v.validUntil], uaTuple(sig)];
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
  // the router's `setGrant`: the nested terms are the call's tuple (governance spec §3.2)
  SetGrant: (m) => [m.target, m.bit, m.holder, ['min', 'max', 'total', 'perWindow', 'window', 'validUntil', 'maxUses', 'delegable',
    'scope'].map((k) => m.terms[k]), m.chainUid],
  // group 3l (wrap limits spec §9): the leg array is the call's array of tuples, each limit a nested tuple
  SetWrapLimits: (m) => [m.target, m.legs.map((l) => [l.underlying, l.unitExp, l.decayDays,
    ...['wrapShort', 'wrapLong', 'unwrapShort', 'unwrapLong'].map((k) => [l[k].perUser, l[k].tokenWide, l[k].period])]),
  m.netUnwrap, m.wrapList, m.unwrapList],
  // the factory's creations (ua-mtx-merge T76): the struct signs `initHash`, the call takes the bytes (`extra`)
  // round 3r: the three publishes take the `Env` tuple; the class approval its words as one static struct (`ReleaseApproval`)
  // CTR-GOV-27: the factory's chain word after the static fields, before `env`; `setChainEntries` takes one named struct
  PublishTokenEnv: (m) => [m.target, m.kind, m.envVersion, m.chainUid, envTuple(m.env)],
  PublishDexEnv: (m) => [m.target, m.envVersion, m.chainUid, envTuple(m.env)],
  PublishClassEnv: (m) => [m.target, m.contractClass, m.kind, m.envVersion, m.chainUid, envTuple(m.env)],
  SetChainEntries: (m) => [m.target, ['relayFeeRouter', 'relayFeeRouterCodeHash', 'relayFeeExecutorCodeHash', 'complianceRegistry',
    'complianceRegistryCodeHash', 'smartKeyAccountFactory', 'smartKeyAccountFactoryCodeHash', 'zetherStatements',
    'zetherStatementsCodeHash'].map((k) => m.entries[k]), m.chainUid],
  ApproveRelease: (m) => [m.target, ['contractClass', 'kind', 'version', 'envVersion', 'initSelector', 'interfaceId', 'initcodeHash',
    'implArgsHash', 'chainUid', 'factory', 'adminGeneration', 'until'].map((k) => m[k])],
  CreateToken: (m, x) => [m.target, m.kind, m.version, x.initArgs, m.salt],
  CreateDex: (m, x) => [m.target, m.version, x.initArgs, m.salt],
  CreateInstance: (m, x) => [m.target, m.contractClass, m.kind, m.version, x.initCall, m.salt],
};
const envelope = (m) => [m.from, m.batch, m.nonce, m.validUntil, m.mode, m.relayer, m.fee, m.feeRecipient];
const tradeTuple = (o) => [o.from, o.receiveToken, o.amount, o.receiveAmount, o.minFill, o.fee, o.relayer, o.dex, o.destination,
  o.flags, o.batch, o.nonce, o.validUntil];
const wrapTuple = (o) => [o.from, o.wrappedToken, o.amount, o.minMinted, o.minFill, o.fee, o.relayer, o.destination, o.flags,
  o.batch, o.nonce, o.validUntil];
const asTrade = (o) => ({ ...o, receiveToken: o.wrappedToken, receiveAmount: o.minMinted, dex: o.wrappedToken });
// pay-meta-tax T41, plan T83: a pay entry's last parameter, `PayMeta {salt, payNo, save, schema, body}`, unsigned
const metaTuple = (x) => [x.salt, x.payNo, x.save, x.schema, x.body];
const transferTuple = (t) => [t.from, t.to, t.value, t.entryRef, t.batch, t.nonce, t.validUntil, t.mode, t.relayer, t.fee, t.feeRecipient];
const OTHER = {
  UAPayeeFee: (m, s, d) => [transferTuple(m.payment), ['0x', d.extra.payerSig, []], m.fee, m.feeRecipient, m.validUntil, ['0x', s, []],
    metaTuple(d.extra.meta)],
  UARelayFee: (m, s) => [m.from, m.target, m.callDataHash, m.payee, m.value, m.batch, m.nonce, m.validUntil, ['0x', s, []]],
  UAPayWithTax: (m, s, d) => [transferTuple(m.payment), m.taxMode, m.tax, ['0x', s, []], metaTuple(d.extra.meta)],
  UAWrapOrder: (m, s, d) => [d.domain.verifyingContract, wrapTuple(m), ['0x', s, []]],
  CancelUAOrder: (m, s) => [tradeTuple(m.order), ['0x', s, []]],
  CancelUAWrapOrder: (m, s) => [tradeTuple(asTrade(m.order)), ['0x', s, []]],
  CancelDexOrder: (m, s) => [[[m.order.sellToken, tradeTuple(m.order.order)]], [s]],
  ZetherRollOver: (m, s) => [m.ua, m.expectedPendingSeq, m.validUntilBlock, ['0x', s, []]],
  ZetherSetRollOverMode: (m, s) => [m.ua, m.mode, m.validUntilBlock, ['0x', s, []]],
};
const ACCOUNT = new Set(['AddKey', 'RemoveKey', 'RotateKey', 'SetGuardian', 'CancelRecovery']);

/** The entry's parameters, in order, from the row alone: `abi.decode` of the row's calldata must equal this. */
export function expectedCall(name, r, d) {
  const m = r.message;
  if (OTHER[name]) return OTHER[name](m, d.signature, d);
  // group 3g: a per-kind row (`UAPqzRollOver`) names its primary type
  const primary = r.primaryType ?? name;
  const base = primary.replace(/^UA/, '');
  const ua = primary !== base;
  const own = CONF[base] ? CONF[base](m, d.extra) : r.types[primary].slice(1, -7).map((f) => m[f.name]);
  const account = ACCOUNT.has(name) || (name === 'Execute' && d.domain.name === 'SCaaS SmartKeyAccount');
  // ua-mtx-merge (R47): every merged entry takes `UASig`, `mtxShield` too; a native id's is `{0x, signature, []}` (R17)
  const sig = account ? ['0', [], d.signature] : ua ? ['0x', d.signature, []] : d.signature;
  const tail = name === 'UAPayUnderMandate' ? [metaTuple(d.extra.meta)] : ua && VERDICT.has(base) ? [verdictTuple(d.extra.pqzVerdict)] : [];
  return [envelope(m), ...own, sig, ...tail];
}

/** Decoded values and `expectedCall` on one form: lower-case hex, decimal strings. */
export const norm = (v) => (Array.isArray(v) ? v.map(norm) : typeof v === 'string' ? v.toLowerCase() : String(v));
