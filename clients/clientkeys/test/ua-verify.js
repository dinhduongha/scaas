// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// The test side of src/ua-verify.js (the verifiers themselves), shared by test/ua-sig.test.js (signatures.json), test/ua8.test.js
// (portable.json) and test/soroban.test.js (ua-ops.json): the lenient msig reading of transaction authorisations.
import { B, bytesAt, wordAt, kindVerify, nativeOk } from '../src/ua-verify.js';
import * as ua from '../src/ua.js';
import { hex } from '../src/bytes.js';

export * from '../src/ua-verify.js';

/** A derived kind's signature over a 32-byte ua_msg, the BLS PoP domain. */
export const sigOk = (kind, keyData, msg, sig) => kindVerify(kind, keyData, msg, sig, true);
/** `abi.decode(blob, (MemberSig[]))`, MemberSig = (uint16 index, InnerSig[] members, bytes sig). */
export function memberSigs(blob) {
  const b = B(blob);
  const a = wordAt(b, 0);
  const base = a + 32;
  return Array.from({ length: wordAt(b, a) }, (_, i) => {
    const t = base + wordAt(b, base + 32 * i);
    const l = t + wordAt(b, t + 32);
    return { index: wordAt(b, t), listLength: wordAt(b, l), sig: bytesAt(b, t, t + 64) };
  });
}
/** An msig signature: indices strictly increasing, each member verifies (derived members over `memberDigest` by key data
 *  from `keyOf`, under `member`; a native member by ECDSA over `nativeDigest`, no key data: the portable record's typed
 *  digest, typed-signing TS-D4; without one a native member is refused), weight at least the threshold. */
export function msigOk(r, md, blob, keyOf, nativeDigest) {
  let weight = 0;
  let last = -1;
  for (const s of memberSigs(blob)) {
    const m = r.members[s.index];
    if (!m || s.index <= last) return false;
    last = s.index;
    const ok = ua.isNativeKind(m.kind)
      ? s.listLength === 0 && nativeDigest !== undefined && nativeOk(`0x${m.id.slice(26)}`, typeof nativeDigest === 'string' ? B(nativeDigest) : nativeDigest, hex(s.sig))
      : s.listLength === 0 && sigOk(m.kind, keyOf(m.id), hex(ua.uaMessage(m.kind, ua.purposeTag('member'), B(md))), hex(s.sig));
    if (!ok) return false;
    weight += m.weight;
  }
  return weight >= r.threshold;
}
