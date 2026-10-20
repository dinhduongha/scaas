// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
import QtQuick
import QtTest
import Scaas.Ua

// Mirrors clients/ua-rs/tests/vectors.rs against the shared vector files.
TestCase {
    name: "UaKinds"

    property var k: vectors.load("kinds.json")
    property var s: vectors.load("structures.json")

    function hex(v) { return v === null ? "" : v }

    function test_table_groups_purposes_constants() {
        verify(k.kinds.length > 0)
        for (const r of k.kinds) {
            const info = JSON.parse(UaKinds.kindInfo(r.kind))
            compare(info.name, r.name)
            compare(info.native, r.native)
            compare(info.lengths, r.lengths, r.name)
            compare(info.group ?? null, r.group ?? null, r.name)
            compare(UaKinds.isNative(r.kind), r.native)
            compare(UaKinds.isSigning(r.kind), r.signing, r.name)
            compare(UaKinds.isZether(r.kind), r.zether, r.name)
            compare(UaKinds.isPqzHolder(r.kind), r.pqzHolder, r.name)
            compare(UaKinds.isMember(r.kind, false), r.member, r.name)
            compare(UaKinds.isMember(r.kind, true), r.memberHedera, r.name)
            if (r.native) {
                compare(UaKinds.tag(r.kind), "")
                compare(UaKinds.lastError, "UAKindNotDerived")
            } else {
                compare(UaKinds.kindTagString(r.kind), r.tag)
                compare(UaKinds.tag(r.kind), r.TAG)
                compare(UaKinds.lastError, "")
            }
        }
        for (const r of k.schemes) {  // schemes are not kinds: tag and keyHash only
            compare(UaKinds.kindTagString(r.kind), r.tag)
            compare(UaKinds.tag(r.kind), r.TAG)
            UaKinds.kindInfo(r.kind)
            compare(UaKinds.lastError, "UAKindUnknown")
            UaKinds.uaOf(r.kind, "0x")
            compare(UaKinds.lastError, "UAKindNotDerived")
            compare(UaKinds.validateKeyData(r.kind, "0x", false), false)
            compare(UaKinds.lastError, "UAKindNotDerived")
        }
        compare(UaKinds.keyHashOf(0x0142, k.pqzKey), k.pqzKeyHash)
        for (const r of k.groups) {
            compare(UaKinds.groupTagString(r.group), r.tag)
            compare(UaKinds.groupTag(r.group), r.GROUP)
        }
        for (const r of k.purposes)
            compare(UaKinds.purposeTag(r.purpose), r.purposeTag)
        compare(UaKinds.msgTag(), k.constants.MSG_TAG)
        compare(UaKinds.purposeTag("pop"), k.constants.POP_TAG)
    }

    function test_valid_rows() {
        for (const r of k.valid) {
            compare(UaKinds.deriveUA(r.kind, r.keyData, r.hederaNative), r.ua, r.name)
            compare(UaKinds.lastError, "", r.name)
            compare(UaKinds.keyHashOf(r.kind, r.keyData), hex(r.keyHash), r.name)
            compare(UaKinds.lastError, "", r.name)
            compare(UaKinds.validateKeyData(r.kind, r.keyData, r.hederaNative), true, r.name)
        }
    }

    function test_invalid_rows() {
        for (const r of k.invalid) {
            compare(UaKinds.validateKeyData(r.kind, r.keyData, r.hederaNative), false, r.reason)
            compare(UaKinds.lastError, r.error, r.reason)
        }
    }

    function test_natives_native_space_canonical_ids() {
        for (const r of k.natives) {
            const id = UaKinds.nativeId(r.kind, r.raw)
            compare(id, r.id)
            compare(UaKinds.canonicalId(id), r.canonical)
        }
        for (const r of k.nativeInvalid) {
            compare(UaKinds.nativeId(r.kind, r.raw), "")
            compare(UaKinds.lastError, r.error)
        }
        for (const r of k.nativeSpace)
            compare(UaKinds.inNativeSpace(r.id), r.inNativeSpace)
        for (const r of k.canonicalIds) {
            const got = UaKinds.canonicalId(r.input)
            if (r.canonical) {
                compare(got, r.canonical)
                compare(UaKinds.lastError, "")
            } else {
                compare(got, "")
                compare(UaKinds.lastError, r.error)
            }
        }
    }

    function test_messages() {
        for (const r of k.messages) {
            const p = UaKinds.purposeTag(r.purpose)
            compare(p, r.purposeTag)
            compare(UaKinds.uaMessage(r.kind, p, r.digest), r.uaMsg)
        }
    }

    function test_structures() {
        for (const p of s.pop) {
            const c = s.contexts[p.context]
            compare(UaKinds.chainKeyHash(c.chainId), p.chainKeyHash)
            compare(UaKinds.popDigest(c.chainId, c.chainUid, c.registry, p.ua, p.pqzKeyHash), p.popDigest)
        }
        for (const p of s.pqzReg) {
            const c = s.contexts[p.context]
            const h = JSON.parse(UaKinds.holderPopMessage(p.kind, c.chainId, c.chainUid, c.registry, p.ua, k.pqzKey))
            compare(h.pqzKeyHash, p.pqzKeyHash)
            compare(h.popDigest, p.popDigest)
            compare(UaKinds.pqzRegMessage(c.chainId, c.chainUid, c.registry, p.ua, k.pqzKey), p.pqzRegMessage)
            for (const bad of [0x0101, 0x0133]) {
                UaKinds.holderPopMessage(bad, c.chainId, c.chainUid, c.registry, p.ua, k.pqzKey)
                compare(UaKinds.lastError, "UAPqzHolder")
            }
            compare(JSON.parse(UaKinds.holderPopMessage(p.kind, c.chainId, c.chainUid, c.registry, p.ua, "")).pqzKeyHash,
                    "0x" + "00".repeat(32))
        }
        for (const p of s.pqzMsig)
            compare(UaKinds.msigPqzEligible(p.keyData), p.eligible, p.reason)
        for (const a of s.uaAuth) {
            const c = s.contexts[a.context]
            compare(UaKinds.uaAuthDomainSeparator(a.generation, c.chainId, c.registry, c.chainUid), a.domainSeparator)
            compare(UaKinds.uaAuthDigest(a.generation, c.chainId, c.registry, c.chainUid, a.ua, a.purposeTag, a.digest), a.uaAuthDigest)
        }
        for (const m of s.member)
            compare(UaKinds.memberDigest(m.structureUa, m.uaMsg), m.memberDigest)
    }

    // binding-level behaviour: malformed input, lastError lifecycle + NOTIFY, encodeMsig
    SignalSpy { id: errSpy; target: UaKinds; signalName: "lastErrorChanged" }

    function test_malformed_input_sets_last_error() {
        compare(UaKinds.deriveUA(0x100, "0xzz", false), "")
        compare(UaKinds.lastError, "UAKeyData")
        compare(UaKinds.uaMessage(0x100, "0x00", "0x00"), "")
        compare(UaKinds.lastError, "UAArgument")
        compare(UaKinds.chainKeyHash(-1), "")
        compare(UaKinds.lastError, "UAArgument")
        compare(UaKinds.kindInfo(0xdead), "")
        compare(UaKinds.lastError, "UAKindUnknown")
        compare(UaKinds.purposeTag("nope"), "")
        compare(UaKinds.lastError, "UAPurposeUnknown")
        compare(UaKinds.canonicalId("1234"), "")
        compare(UaKinds.lastError, "UAIdFormat")
    }

    function test_malformed_numbers_and_hex() {
        for (const bad of [NaN, Infinity, -1, 1.5, 9007199254740994, 2 ** 64]) {
            compare(UaKinds.chainKeyHash(bad), "", String(bad))
            compare(UaKinds.lastError, "UAArgument", String(bad))
        }
        // kinds outside 0..0xFFFF (an int parameter: QML wraps beyond int32 before the binding sees the value)
        for (const bad of [-1, 0x10100, 0x7fffffff]) {
            compare(UaKinds.kindInfo(bad), "", String(bad))
            compare(UaKinds.lastError, "UAArgument", String(bad))
        }
        // digests: odd-length hex and a "0X" prefix are not hex; a wrong length is an argument error
        compare(UaKinds.purposeTag("pop") !== "", true)
        compare(UaKinds.memberDigest("0x" + "0".repeat(63), "0x" + "0".repeat(64)), "")
        compare(UaKinds.lastError, "UAArgument")
        compare(UaKinds.memberDigest("0X" + "0".repeat(64), "0x" + "0".repeat(64)), "")
        compare(UaKinds.lastError, "UAArgument")
        compare(UaKinds.memberDigest("0x00", "0x" + "0".repeat(64)), "")
        compare(UaKinds.lastError, "UAArgument")
        // key data (nativeId raw, keyHashOf, deriveUA): undecodable is UAKeyData
        for (const bad of ["0xabc", "0X00", "0xzz"]) {
            compare(UaKinds.nativeId(0x0001, bad), "", bad)
            compare(UaKinds.lastError, "UAKeyData", bad)
            compare(UaKinds.keyHashOf(0x0100, bad), "", bad)
            compare(UaKinds.lastError, "UAKeyData", bad)
            compare(UaKinds.deriveUA(0x0100, bad, false), "", bad)
            compare(UaKinds.lastError, "UAKeyData", bad)
        }
    }

    function test_last_error_cleared_and_notifies() {
        UaKinds.msgTag()                       // lastError "" before
        errSpy.clear()
        UaKinds.purposeTag("nope")
        compare(errSpy.count, 1)
        UaKinds.msgTag()                       // success clears it
        compare(errSpy.count, 2)
        compare(UaKinds.lastError, "")
    }

    function test_encode_msig() {
        const id = "0x" + "11".repeat(32)
        compare(UaKinds.encodeMsig(2, JSON.stringify([[256, id, 1], [257, id, 1]])),
                "0x00020002" + "0100" + "11".repeat(32) + "0001" + "0101" + "11".repeat(32) + "0001")
        compare(UaKinds.encodeMsig(1, "not json"), "")
        compare(UaKinds.lastError, "UAArgument")
    }
}
