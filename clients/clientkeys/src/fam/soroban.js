// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Soroban (plan 2026-11-17-scaas-sdk T24.soroban, spec §8.7): the `getLedgerEntries` keys of a holder's balances and the entry
// data they answer, in XDR (Stellar-ledger-entries.x): a `G…` account's entry (its native stroops), the `Balance(Address)`
// entry of a token or of the XLM SAC (a `C…` holder's native XLM), and the token's `UaBalance(BytesN<32>)` entry of a UA id
// (smartcontracts/soroban/contracts/token: persistent storage). Rows: smartcontracts/vectors/families/soroban.json
// (scripts/families-vectors.mjs), read by the SDK's reader and the node's XDR crate. UNAUDITED.
import { base64 } from "@scure/base";
import * as S from "../soroban.js";
import { concatBytes, fromHex, hex, sha256, utf8ToBytes } from "../bytes.js";

const u32 = (n) => Uint8Array.of(n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
const ACCOUNT = 0;
const CONTRACT_DATA = 6;
const PERSISTENT = 1;
/** `ScAddress` of a strkey: the `ScVal::Address` without its ScVal tag. */
const scAddress = (text) => S.addr(text).xdr.slice(4);

/** The token's storage key of a holder: `Balance(Address)` for a `G…` / `C…`, `UaBalance(BytesN<32>)` for a `0x` UA id. */
export function holderKey(holder) {
  if (/^0x[0-9a-f]{64}$/.test(holder)) return S.vec([S.sym("UaBalance"), S.bytes(fromHex(holder))]);
  return S.vec([S.sym("Balance"), S.addr(holder)]);
}

/** `LedgerKey::Account` of a `G…`. */
export function accountKey(g) {
  const { contract, payload } = S.decodeStrkey(g);
  if (contract) throw new Error("an account key of a contract");
  return concatBytes(u32(ACCOUNT), u32(0), payload);
}

/** `LedgerKey::ContractData` of `contract` (a `C…`) at `holder`'s balance key, persistent. */
export function balanceKey(contract, holder) {
  if (!S.decodeStrkey(contract).contract) throw new Error("a token that is no contract");
  return concatBytes(u32(CONTRACT_DATA), scAddress(contract), holderKey(holder).xdr, u32(PERSISTENT));
}

/** `LedgerEntryData::Account` with `balance` stroops and every other field empty (thresholds 1/0/0/0, ext v0). */
export function accountEntry(g, balance, seq = 1n) {
  const { payload } = S.decodeStrkey(g);
  const i64 = (n) => S.u64(BigInt.asUintN(64, BigInt(n))).xdr.slice(4);
  return concatBytes(
    u32(ACCOUNT),
    u32(0),
    payload,
    i64(balance),
    i64(seq),
    u32(0), // numSubEntries
    u32(0), // inflationDest: none
    u32(0), // flags
    u32(0), // homeDomain ""
    Uint8Array.of(1, 0, 0, 0), // thresholds
    u32(0), // signers
    u32(0), // ext v0
  );
}

/** `LedgerEntryData::ContractData` of a balance key holding `val` (an ScVal). */
export function balanceEntry(contract, holder, val) {
  return concatBytes(u32(CONTRACT_DATA), u32(0), scAddress(contract), holderKey(holder).xdr, u32(PERSISTENT), val.xdr);
}

/** A token's balance value: `I128`. */
export const tokenValue = (amount) => S.i128(amount);
/** The SAC's balance value: `{amount: I128, authorized: bool, clawback: bool}`. */
export const sacValue = (amount, authorized = true, clawback = false) =>
  S.struct({ amount: S.i128(amount), authorized: S.bool(authorized), clawback: S.bool(clawback) });

// ---- T27.soroban (CLI-SGN-22, CLI-SGN-27; spec 2026-11-17-scaas-sdk §27.3 (b)): a `G…` subject's op envelope, the host
// authorization of a token entry (NET-SOR-01, NET-SOR-16), from named fields. What is signed is `authDigest` of the
// `HashIdPreimage::SorobanAuthorization` rebuilt here; the node rebuilds the same bytes from the same named `payload`.
export class SorobanError extends Error {}
const refuse = (why) => {
  throw new SorobanError(`Refusing to sign: ${why}`);
};
/** The entries a `G…` subject signs, each argument by the contract's name and type (smartcontracts/soroban/contracts/token). */
export const OP_KINDS = Object.freeze({
  transfer: [
    ["from", "Address"],
    ["to", "Address"],
    ["amount", "i128"],
  ],
  pay: [
    ["from", "Address"],
    ["to", "Address"],
    ["amount", "i128"],
    ["pay_ref", "BytesN<32>"],
    ["valid_until", "u64"],
  ],
  burn: [
    ["from", "Address"],
    ["amount", "i128"],
  ],
});
const I128_MAX = (1n << 127n) - 1n;
const strkeyOf = (t) => {
  try {
    return S.decodeStrkey(t);
  } catch {
    return null;
  }
};
const isAccount = (t) => strkeyOf(t)?.contract === false;

/** `sha256(passphrase)`, the network id. */
export const networkIdOf = (passphrase) => S.networkId(passphrase);

/** The invocation of `kind` on `contract` with the named `fields`, its arguments as the node's job values. */
export function opInvocation({ contract, kind, fields }) {
  const spec = OP_KINDS[kind];
  if (!spec) refuse(`no Soroban op ${kind}`);
  return {
    contract,
    function: kind,
    args: spec.map(([n, type]) => ({ type, value: fields[n] })),
    sub_invocations: [],
  };
}

/** NET-SOR-02's deterministic host nonce of a `pay`: `i64(sha256("scaas.soroban.nonce" ‖ pay_ref ‖ be64(valid_until))[0..8])`. */
export function payNonce(payRef, validUntil) {
  const h = sha256(concatBytes(utf8ToBytes("scaas.soroban.nonce"), fromHex(payRef), be64(BigInt(validUntil))));
  return BigInt.asIntN(64, BigInt(hex(h.slice(0, 8))));
}
const be64 = (n) => {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt.asUintN(64, n));
  return b;
};

/** CLI-SGN-27: the payload rebuilt from `terms` (`{networkId, contract, kind, fields, nonce, expiry, ledger, window}`) against
 *  `shown` (`{passphrase, contract, kind, from, to?, amount}`, the user's own input); a frozen `{payload, walletInput,
 *  signingBytes}`, or `SorobanError` "Refusing to sign: …" for each must-check. */
export function checkTerms(terms, shown) {
  const { networkId, contract, kind, fields = {}, nonce, expiry, ledger, window } = terms;
  const spec = OP_KINDS[kind];
  if (!spec) refuse(`no Soroban op ${kind}`);
  if (kind !== shown.kind) refuse("the entry is not the one shown");
  if (contract !== shown.contract || strkeyOf(contract)?.contract !== true)
    refuse("the contract is not the token shown");
  const names = spec.map(([n]) => n);
  if (Object.keys(fields).some((k) => !names.includes(k))) refuse("a field the entry does not take");
  if (!isAccount(fields.from) || fields.from !== shown.from) refuse("from is not the account shown");
  if (names.includes("to") && (fields.to !== shown.to || !strkeyOf(fields.to))) refuse("to is not the recipient shown");
  // a canonical decimal string: digits only, no leading zero (the node's job value is this text)
  const amount = /^[1-9][0-9]{0,38}$/.test(String(fields.amount)) ? BigInt(fields.amount) : -1n;
  if (amount <= 0n || amount > I128_MAX || String(fields.amount) !== String(shown.amount))
    refuse("the amount is not the positive amount shown");
  if (kind === "pay" && !/^0x[0-9a-f]{64}$/.test(String(fields.pay_ref))) refuse("pay_ref is no 32 bytes");
  if (kind === "pay" && !(Number.isSafeInteger(fields.valid_until) && fields.valid_until > 0))
    refuse("valid_until is no time");
  if (hex(fromHex(networkId)) !== hex(S.networkId(shown.passphrase)))
    refuse("network_id is not the configured network's");
  if (!(Number.isInteger(expiry) && expiry >= ledger && expiry <= ledger + window))
    refuse("the expiry ledger is out of its window");
  const n = BigInt(nonce);
  if (n !== BigInt.asIntN(64, n)) refuse("the nonce is no i64");
  const invocation = opInvocation({ contract, kind, fields });
  const p = { networkId: fromHex(networkId), nonce: n, expiry, invocation };
  return Object.freeze({
    payload: Object.freeze({ nonce: String(n), expiry, invocation }),
    walletInput: base64.encode(S.authPreimage(p)),
    signingBytes: S.authDigest(p),
  });
}

/** The submit form of a `G…` key's signature over `checked.signingBytes`: 64 bytes hex, the key's strkey. */
export function packSignature(checked, key, sig) {
  if (!checked || !Object.isFrozen(checked)) refuse("only a checkTerms result is signed");
  if (!(sig instanceof Uint8Array) || sig.length !== 64) refuse("an ed25519 signature is 64 bytes");
  return { signature: hex(sig), publicKey: key.address };
}

/** The node's `signed_op` of `POST /v1/ops` (docs/node/job-api.md#soroban-signed-op), every field named. */
export const signedOp = (checked, packed, { contract, validUntil }) => ({
  family: "soroban",
  payload: checked.payload,
  from: packed.publicKey,
  signature: packed.signature,
  contract,
  valid_until: validUntil,
});

// ---- T41.soroban (spec §27.5 (d)): the native transaction from named fields, `Transaction` XDR (Stellar-transaction.x), its
// signature base `sha256(network_id ‖ ENVELOPE_TYPE_TX ‖ tx)` and the `TransactionEnvelope` v1. A self-relay carries one
// `InvokeHostFunctionOp` (the subject's auth entry, the `SorobanTransactionData` its payer's simulation gave); a native send one
// `Payment` of XLM. Ledger keys of the footprint stay XDR (one ledger object each), base64 as the RPC answers them.
const ENVELOPE_TYPE_TX = 2;
const opaqueX = (b) => concatBytes(u32(b.length), b, new Uint8Array((4 - (b.length % 4)) % 4));
const i64 = (n) => be64(BigInt.asUintN(64, BigInt(n)));
const u64x = (n) => be64(BigInt(n));
const fromB64 = (s) => base64.decode(s);
const muxed = (g) => {
  const { contract, payload } = S.decodeStrkey(g);
  if (contract) refuse("a transaction account is a G…");
  return concatBytes(u32(0), payload);
};
const array = (items) => concatBytes(u32(items.length), ...items);

/** A `G…` account's auth credential signature as the host reads it: `Vec[Map{public_key: Bytes, signature: Bytes}]`. */
export function accountSignature(g, sig) {
  const { payload } = S.decodeStrkey(g);
  return S.vec([S.struct({ public_key: S.bytes(payload), signature: S.bytes(fromHex(sig)) })]);
}
/** `SorobanAuthorizationEntry` of a `{payload, from, signature}` (Address credentials), or of `{source: true, invocation}`
 *  (SourceAccount credentials: the transaction's source authorizes, its own signature covering it). */
export function authEntry({ source, invocation, payload, from, signature }) {
  // the transaction's source account's own authorization (owner 2026-11-22: a self-paid op, its subject the source)
  if (source === true) return concatBytes(u32(0), S.invocationXdr(invocation));
  return concatBytes(
    u32(1),
    scAddress(from),
    i64(BigInt(payload.nonce)),
    u32(payload.expiry),
    accountSignature(from, signature).xdr,
    S.invocationXdr(payload.invocation),
  );
}
/** `SorobanTransactionData`: ext v0 (none archived) or v1 (`archived` indexes), the footprint, the resources, the fee. */
export function sorobanData({
  readOnly,
  readWrite,
  instructions,
  diskReadBytes,
  writeBytes,
  resourceFee,
  archived = [],
}) {
  return concatBytes(
    archived.length ? concatBytes(u32(1), array(archived.map(u32))) : u32(0),
    array(readOnly.map(fromB64)),
    array(readWrite.map(fromB64)),
    u32(instructions),
    u32(diskReadBytes),
    u32(writeBytes),
    i64(BigInt(resourceFee)),
  );
}

/** `Transaction` XDR: `{source, fee, seq, minTime, maxTime, op}`, `op` = `{invoke: {invocation, auth, data}}` or
 *  `{payment: {destination, amount}}` (XLM, stroops). Refused: a sequence not above 0, no time bound, a payment not above 0. */
export function nativeTx({ source, fee, seq, minTime, maxTime, op }) {
  if (BigInt(seq) <= 0n) refuse("the sequence is not above 0");
  if (!(BigInt(maxTime) > 0n && BigInt(minTime) <= BigInt(maxTime))) refuse("the transaction has no time bound");
  if (!Number.isInteger(fee) || fee < 0 || fee > 0xffffffff) refuse("the fee is no u32");
  let body, ext;
  if (op.invoke) {
    const { invocation, auth, data } = op.invoke;
    if (invocation.sub_invocations.length) refuse("a host call is one contract function");
    // a SourceAccount entry only when the transaction's source is the op's subject (its `from`)
    if (auth.some((a) => a.source === true) && invocation.args[0]?.value !== source)
      refuse("a SourceAccount entry under a source that is not the subject");
    const call = S.invocationXdr(invocation).slice(4, -4); // InvokeContractArgs: the invocation without its tag and sub list
    body = concatBytes(u32(24), u32(0), call, array(auth.map(authEntry)));
    ext = concatBytes(u32(1), sorobanData(data));
  } else if (op.payment) {
    const amount = BigInt(op.payment.amount);
    if (amount <= 0n || amount !== BigInt.asIntN(64, amount)) refuse("the payment is not a positive i64");
    body = concatBytes(u32(1), muxed(op.payment.destination), u32(0), i64(amount));
    ext = u32(0);
  } else refuse("an operation of no known kind");
  return concatBytes(
    muxed(source),
    u32(fee),
    i64(BigInt(seq)),
    u32(1),
    u64x(minTime),
    u64x(maxTime),
    u32(0),
    array([concatBytes(u32(0), body)]),
    ext,
  );
}
/** The signature base's hash, the transaction id. */
export const txHash = (networkId, tx) => sha256(concatBytes(fromHex(networkId), u32(ENVELOPE_TYPE_TX), tx));
/** `TransactionEnvelope` v1 with one `DecoratedSignature` of the `G…` source: its key's last 4 bytes, the 64 bytes. */
export function envelope(tx, g, sig) {
  const { payload } = S.decodeStrkey(g);
  return concatBytes(u32(ENVELOPE_TYPE_TX), tx, array([concatBytes(payload.slice(28), opaqueX(fromHex(sig)))]));
}

// ---- footprint keys the vectors and the reads name
/** `LedgerKey::ContractData` of the host nonce `nonce` of account `g` (temporary): present once the nonce is used (NET-SOR-12). */
export const nonceKey = (g, nonce) =>
  concatBytes(u32(CONTRACT_DATA), scAddress(g), u32(21), i64(BigInt(nonce)), u32(0));
/** `LedgerKey::ContractData` of the token's `PayRef(from, pay_ref)` entry (persistent; NET-SOR-09). */
export const payRefKey = (contract, from, payRef) =>
  concatBytes(
    u32(CONTRACT_DATA),
    scAddress(contract),
    S.vec([S.sym("PayRef"), S.addr(from), S.bytes(fromHex(payRef))]).xdr,
    u32(PERSISTENT),
  );
/** `LedgerKey::ContractData` of a contract's instance (persistent) and `LedgerKey::ContractCode` of a Wasm hash. */
export const instanceKey = (contract) => concatBytes(u32(CONTRACT_DATA), scAddress(contract), u32(20), u32(PERSISTENT));
export const codeKey = (hash) => concatBytes(u32(7), fromHex(hash));
