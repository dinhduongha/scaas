// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// The regulated kinds 8-13 off chain (regulated-kinds spec §3.1, §3.3, §3.6, §5): the bytes a wallet reproduces and the
// freeze transitions T1-T9 it shows, against smartcontracts/vectors/governance/regulated_kat.json (written by forge,
// RegulatedKat.t.sol). The contract decides; nothing here is a check of record. UNAUDITED.
import { hex, keccak_256, utf8ToBytes, abiEncode } from './bytes.js';

const ZERO = '0x' + '00'.repeat(32);
const pad = (address) => '0x' + '00'.repeat(12) + address.slice(2).toLowerCase();
const poolOf = (tag) => pad(hex(keccak_256(utf8ToBytes(tag)).subarray(12)));
/** `pad(MetaTxLib.UA_POOL)`, `pad(MetaTxLib.SHIELD_POOL)`. */
export const UA_POOL_ID = poolOf('scaas.ua.pool.v1');
export const SHIELD_POOL_ID = poolOf('scaas.shield.pool.v1');
export const ELIGIBLE_CONTRACT = 8n;
/** `RegulatedLib`'s `controls` bits (bits 5-10 of `features`, shifted down by 5; bit 28 `KYC` in byte bit 6, round 3s)
 *  and spans (spec §3.5). */
export const C_FREEZE = 1;
export const C_ALLOW = 1 << 3;
export const C_DENY = 1 << 4;
export const C_RECORD = 1 << 5;
export const C_KYC = 1 << 6;
/** Round 3s (spec 2026-11-10-token-lists.md §4.1): an account's `listFlagsOf` byte. */
export const ALLOWED = 1;
export const DENIED = 2;
const DAY = 86400n;
export const FREEZE_SPAN = 30n * DAY;
export const EPISODE_SPAN = 60n * DAY;
export const FREEZE_COOLDOWN = 30n * DAY;
/** The actions a pending commits to (spec §3.6). */
export const ACTION = Object.freeze({ GRANT: 1, SET: 2, REVOKE: 3, RENOUNCE: 4, DISABLE: 5 });
const TERMS = ['uint128', 'uint128', 'uint128', 'uint128', 'uint32', 'uint64', 'uint32', 'bool', 'bytes32'];
const TERM_NAMES = ['min', 'max', 'total', 'perWindow', 'window', 'validUntil', 'maxUses', 'delegable', 'scope'];

/** `recordId = keccak256(abi.encode(orderId, subject, beneficiary))` (spec §3.1). */
export function recordId(orderId, subject, beneficiary) {
  return hex(keccak_256(abiEncode(['bytes32', 'bytes32', 'bytes32'], [orderId, subject, beneficiary])));
}

/** `commit = keccak256(abi.encode(uint8 action, uint8 bit, bytes32 account, bytes32 argsHash))`; `argsHash` is
 *  `keccak256(abi.encode(GrantTerms))` for `SET`, else 0 (spec §3.6). */
export function relaxCommit(action, bit, account, terms) {
  if (!Object.values(ACTION).includes(action)) throw new Error(`no action ${action}`);
  if ((action === ACTION.SET) !== (terms !== undefined)) throw new Error('terms go with SET only');
  const args = terms === undefined ? ZERO
    : hex(keccak_256(abiEncode(TERMS, TERM_NAMES.map((k) => (k === 'delegable' || k === 'scope' ? terms[k] : BigInt(terms[k]))))));
  return hex(keccak_256(abiEncode(['uint8', 'uint8', 'bytes32', 'bytes32'], [action, bit, account, args])));
}

/** `R(account)` as `canReceive` answers it under `KYC` (spec §3.1, §5; round 3s §3): `{ok, reason}`, reason 1 not attested or
 *  flags missing, 2 expired, 3 KYC provider disabled, 4 denied (`kycProviderEnabled`: the registry's answer for the row's
 *  provider); `ok` is `hasFlags(account, requiredFlags, deniedFlags)` (a zero mask constrains nothing), `KYC` off `(true, 0)`
 *  with no call. The lists come first on chain: `listed`. */
export function canReceive({ controls, requiredFlags, deniedFlags, flags, validUntil, kycProviderEnabled, now }) {
  if (!(controls & C_KYC)) return { ok: true, reason: 0 };
  const [f, until, t] = [BigInt(flags), BigInt(validUntil), BigInt(now)];
  const active = kycProviderEnabled && until >= t;
  const req = BigInt(requiredFlags);
  if (req !== 0n && !(active && ((f & req) === req || (f & ELIGIBLE_CONTRACT) !== 0n))) {
    return { ok: false, reason: until === 0n ? 1 : !kycProviderEnabled ? 3 : !active ? 2 : 1 };
  }
  if (active && (f & BigInt(deniedFlags)) !== 0n) return { ok: false, reason: 4 };
  return { ok: true, reason: 0 };
}

/** `L(account)` as `canReceive` answers it first (round 3s, spec §4.2, §4.3): under `ALLOWLIST` not `ALLOWED` reason 5,
 *  under `DENYLIST` `DENIED` reason 6, else `(true, 0)`. `listFlags` is `listFlagsOf(account)`. */
export function listed(controls, listFlags) {
  if (controls & C_ALLOW && !(listFlags & ALLOWED)) return { ok: false, reason: 5 };
  if (controls & C_DENY && listFlags & DENIED) return { ok: false, reason: 6 };
  return { ok: true, reason: 0 };
}

const ENABLEABLE = (1n << 8n) | (1n << 9n) | (1n << 28n);
/** `admin` / `registry` as given: a boolean, or the on-chain id (a bytes32 UA or an address, hex); 0, false or absent is none. */
const none = (v) => v == null || BigInt(v) === 0n;
/** Spec §5.5 (round 3s): the bits of 8, 9, 28 that can still be switched on (`enableFeature`): valid for the kind, not set,
 *  not locked (off), the admin not 0, and for 28 a compliance registry. `admin` and `registry` a boolean or the views' id
 *  (`'0x00…00'` is none, as on chain). A wallet prints a bit's `enableable` sentence of governance_bits.json only then, and
 *  never for a bit locked off. */
export function enableable({ features, lockedFeatures, valid, admin, registry }) {
  if (none(admin)) return 0n;
  let e = ENABLEABLE & BigInt(valid) & ~BigInt(features) & ~BigInt(lockedFeatures);
  if (none(registry)) e &= ~(1n << 28n);
  return e;
}

const refused = (sig, ...args) => ({ error: { sig, args: args.map(String) } });
/** A freeze that counts (`frozen(a)` of §3.3 with the `controls` term): `until > now`, record-backed only while `RECORD`. */
export const counts = (s, controls, now) => BigInt(s.until) > BigInt(now) && (!s.recordBacked || (controls & C_RECORD) !== 0);
/** `F(a)`, the issuer roots taken as live. */
export const frozen = (s, controls, now) => (controls & C_FREEZE) !== 0 && counts(s, controls, now);

/** One call of §3.3 on an account's `FreezeState` (`until`, `episodeStart`, `issuerCooldownUntil` as decimal strings,
 *  `recordBacked`, `recordId`): `{after}` or `{error: {sig, args}}`. `call.fn` is `freeze`, `unfreeze` or `revokeOrder`
 *  (`record`: the order `call.recordId` names, `{subject, freezeUntil, revoked}`, or null). The role gate (`use`) is the
 *  contract's and not modelled. */
export function freezeStep(before, { fn, account, ref, recordId: rid, reasonRef }, { now, controls, token, record }) {
  const s = { ...before };
  const t = BigInt(now);
  const end = () => Object.assign(s, { until: String(t), recordBacked: false, recordId: ZERO,
    issuerCooldownUntil: String(t + FREEZE_COOLDOWN) });
  const on = counts(s, controls, now);
  const live = () => {
    if (!record) return refused('OrderUnknown(bytes32)', rid);
    if (record.revoked || !(controls & C_RECORD)) return refused('OrderInactive(bytes32)', rid);
    return null;
  };
  if (fn === 'freeze') {
    if ([ZERO, UA_POOL_ID, SHIELD_POOL_ID, pad(token)].includes(account.toLowerCase())) return refused('FreezeTargetRefused(bytes32)', account);
    if (ref === ZERO) return refused('RefRequired()');
    if (rid === ZERO) {
      if (!on) {
        if (t < BigInt(s.issuerCooldownUntil)) return refused('FreezeCooldown(uint64)', s.issuerCooldownUntil);
        Object.assign(s, { episodeStart: String(t), until: String(t + FREEZE_SPAN), recordBacked: false, recordId: ZERO });
      } else {
        if (s.recordBacked) return refused('AlreadyRecordFrozen(bytes32)', account);
        const cap = BigInt(s.episodeStart) + EPISODE_SPAN;
        const n = t + FREEZE_SPAN < cap ? t + FREEZE_SPAN : cap;
        if (n <= BigInt(s.until)) return refused('FreezeTooLong(uint64)', cap);
        s.until = String(n);
      }
      s.issuerCooldownUntil = String(BigInt(s.until) + FREEZE_COOLDOWN);
      return { after: s };
    }
    const no = live();
    if (no) return no;
    if (record.subject !== account || BigInt(record.freezeUntil) <= t) return refused('OrderInactive(bytes32)', rid);
    if (on && BigInt(record.freezeUntil) < BigInt(s.until)) return refused('RecordFreezeShorter(uint64)', s.until);
    Object.assign(s, { until: String(record.freezeUntil), recordBacked: true, recordId: rid });
    return { after: s };
  }
  if (fn === 'unfreeze') {
    if (ref === ZERO) return refused('RefRequired()');
    if (!on) return refused('NotFrozen(bytes32)', account);
    end();
    return { after: s };
  }
  if (fn === 'revokeOrder') {
    if (reasonRef === ZERO) return refused('RefRequired()');
    if (!record) return refused('OrderUnknown(bytes32)', rid);
    if (record.revoked) return refused('OrderInactive(bytes32)', rid);
    if (s.recordId === rid && on) end();
    return { after: s };
  }
  throw new Error(`no transition ${fn}`);
}
