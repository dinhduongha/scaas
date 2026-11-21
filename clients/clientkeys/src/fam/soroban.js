// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// Soroban (plan 2026-11-17-scaas-sdk T24.soroban, spec §8.7): the `getLedgerEntries` keys of a holder's balances and the entry
// data they answer, in XDR (Stellar-ledger-entries.x): a `G…` account's entry (its native stroops), the `Balance(Address)`
// entry of a token or of the XLM SAC (a `C…` holder's native XLM), and the token's `UaBalance(BytesN<32>)` entry of a UA id
// (smartcontracts/soroban/contracts/token: persistent storage). Rows: smartcontracts/vectors/families/soroban.json
// (scripts/families-vectors.mjs), read by the SDK's reader and the node's XDR crate. UNAUDITED.
import * as S from "../soroban.js";
import { concatBytes, fromHex } from "../bytes.js";

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
