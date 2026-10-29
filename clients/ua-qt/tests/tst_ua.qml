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
            compare(UaKinds.purposeTagV(r.purpose, r.version), r.purposeTag, r.purpose)
        compare(UaKinds.purposeTag("kem"), k.purposes.find(r => r.purpose === "kem").purposeTag)
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
            const p = UaKinds.purposeTagV(r.purpose, r.version ?? 1)
            compare(p, r.purposeTag)
            compare(UaKinds.uaMessage(r.kind, p, r.digest), r.uaMsg)
        }
    }

    function test_portable() {
        const pp = vectors.load("portable.json")
        compare(UaKinds.purposeTagV("pop", 2), pp.tags.PURPOSE_POP_V2.hash)
        compare(UaKinds.purposeTag("kem"), pp.tags.PURPOSE_KEM.hash)
        compare(UaKinds.purposeTag("pqz-key"), pp.tags.PURPOSE_PQZ_KEY.hash)
        compare(pp.registrations.length, 25)
        let withPqz = 0
        for (const r of pp.registrations) {
            const a = r.attrs
            const h = JSON.parse(UaKinds.holderPopMessage(r.kind, r.ua, r.keyData, a.pqzKey, r.pqzPop, Number(a.kemVersion), a.kemPk))
            compare(UaKinds.lastError, "", r.name)
            compare(h.pqzKeyHash, r.pqzKeyHash, r.name)
            compare(h.pqzPopHash, a.pqzPopHash, r.name)
            compare(h.kemRecordHash, r.kemRecordHash, r.name)
            compare(h.portablePopDigest, r.portablePopDigest, r.name)
            compare(h.registrationDigest, r.registrationDigest, r.name)
            compare(h.message, r.popMessage, r.name)
            compare(h.memberDigest ?? "", r.memberDigest ?? "", r.name)
            compare(UaKinds.portablePopDigest(r.ua, h.pqzKeyHash, h.kemRecordHash), r.portablePopDigest)
            compare(UaKinds.registrationDigest(r.portablePopDigest, h.pqzPopHash), r.registrationDigest)
            if (a.pqzKey !== "0x") {
                withPqz++
                compare(UaKinds.pqzRegMessage(r.ua, a.pqzKey, Number(a.kemVersion), a.kemPk), r.pqzRegMessage, r.name)
            }
        }
        compare(withPqz, 8)
        // hash-only proof path agrees with the proof bytes
        for (const r of pp.registrations) {
            const a = r.attrs
            if (a.pqzKey === "0x")
                continue
            const h = JSON.parse(UaKinds.holderPopMessageH(r.kind, r.ua, r.keyData, a.pqzKey, "0x", a.pqzPopHash, Number(a.kemVersion), a.kemPk))
            compare(UaKinds.lastError, "", r.name)
            compare(h.message, r.popMessage, r.name)
        }
        // the portable.json negatives that are digest-layer rules (as ua-rs / ua-cs)
        let run = 0
        for (const n of pp.negatives) {
            const m = n.mutation, set = m.set ?? {}
            const only = Object.keys(set).every(x => x.startsWith("attrs.") || x === "pqzPop")
            if ((n.entry === "register" || n.entry === "storePqzPop") && only) {
                const row = JSON.parse(JSON.stringify(pp.registrations.find(r => r.name === m.row)))
                for (const [key, v] of Object.entries(Object.assign({}, m.registerWith ?? {}, set))) {
                    if (key.startsWith("attrs.")) row.attrs[key.slice(6)] = v; else row[key] = v
                }
                const a = row.attrs
                const out = UaKinds.holderPopMessageH(row.kind, row.ua, row.keyData, a.pqzKey, row.pqzPop, a.pqzPopHash, Number(a.kemVersion), a.kemPk)
                if (n.error === "UAPoP") {
                    compare(UaKinds.lastError, "", n.name)
                    verify(JSON.parse(out).message !== row.popMessage, n.name)
                } else {
                    compare(UaKinds.lastError, n.error, n.name)
                }
                run++
            } else if (n.entry === "setPqzKey" && ["UAPqzKeySet", "UAPqzHolder", "UAPqzPopHash"].includes(n.error)) {
                const rec = pp.pqzKeyRecords.find(r => r.name === m.row)
                const ua = set.ua ?? rec.ua
                const holder = pp.registrations.find(r => r.ua === ua)
                UaKinds.pqzKeyRecordMessage(holder.kind, ua, holder.keyData, rec.pqzKey, "0x", set.pqzPopHash ?? rec.pqzPopHash, n.error === "UAPqzKeySet")
                compare(UaKinds.lastError, n.error, n.name)
                run++
            } else if (n.entry === "setKemKey" && n.name === "kem-record-of-other-ua") {
                const kr = pp.kemRecords.find(r => r.id === m.row)
                const t = pp.registrations.find(r => r.ua === set.ua)
                const d = UaKinds.kemRecordDigest(set.ua, Number(kr.version), kr.kemPk)
                verify(UaKinds.uaMessage(t.kind, UaKinds.purposeTag("kem"), d) !== kr.message, n.name)
                run++
            }
        }
        compare(run, 56)
        // refusals
        const proof = "0x" + "07".repeat(32), ua = "0x" + "01".repeat(32)
        for (const bad of [0x0101, 0x0133]) {  // single-key non-holders refuse a PQZ key (on every pqzReg row's UA)
            for (const p of s.pqzReg) {
                UaKinds.holderPopMessage(bad, p.ua, "0x", k.pqzKey, proof, 0, "")
                compare(UaKinds.lastError, "UAPqzHolder")
            }
        }
        UaKinds.holderPopMessage(0x0130, ua, "0x", k.pqzKey, "0x", 0, "")
        compare(UaKinds.lastError, "UAPqzPopHash")  // a PQZ key without its proof
        UaKinds.holderPopMessage(0x0120, ua, "0x000200", k.pqzKey, proof, 0, "")
        compare(UaKinds.lastError, "UAKeyData")
        UaKinds.holderPopMessage(0x0120, ua, "0x", k.pqzKey, proof, 0, "")
        compare(UaKinds.lastError, "UAPqzHolder")
        UaKinds.holderPopMessage(0x0101, ua, "0x", "0x", "0x", 1, "0x" + "00".repeat(1600))
        compare(UaKinds.lastError, "UAKemHolder")
    }

    function test_pqzKeyRecord() {
        const pp = vectors.load("portable.json")
        compare(pp.pqzKeyRecords.length, 8)
        for (const r of pp.pqzKeyRecords) {
            const reg = pp.registrations.find(x => x.ua === r.ua)
            const pop = pp.registrations.find(x => x.set === r.set).pqzPop
            for (const hashOnly of [false, true]) {
                const g = JSON.parse(UaKinds.pqzKeyRecordMessage(r.kind, r.ua, reg.keyData, r.pqzKey, hashOnly ? "0x" : pop, hashOnly ? r.pqzPopHash : "0x", false))
                compare(UaKinds.lastError, "", r.name)
                compare(g.pqzKeyHash, r.pqzKeyHash, r.name)
                compare(g.pqzPopHash, r.pqzPopHash, r.name)
                compare(g.pqzKeyDigest, r.pqzKeyDigest, r.name)
                compare(g.recordDigest, r.recordDigest, r.name)
                compare(g.message, r.message, r.name)
                compare(g.pqzRegMessage, r.pqzRegMessage, r.name)
                compare(g.memberDigest !== undefined, r.kind === 0x0120, r.name)
            }
            UaKinds.pqzKeyRecordMessage(r.kind, r.ua, reg.keyData, r.pqzKey, "0x", r.pqzPopHash, true)
            compare(UaKinds.lastError, "UAPqzKeySet", r.name)
        }
    }

    function test_kemRecord() {
        const pp = vectors.load("portable.json")
        compare(pp.kemRecords.length, 9)
        for (const r of pp.kemRecords) {
            const d = UaKinds.kemRecordDigest(r.ua, Number(r.version), r.kemPk)
            compare(d, r.digest, r.id)
            compare(UaKinds.uaMessage(r.kind, UaKinds.purposeTag("kem"), d), r.message, r.id)
            if (r.kind === 0x0120)
                compare(UaKinds.memberDigest(r.ua, r.message), r.memberDigest, r.id)
        }
        const ua = "0x" + "01".repeat(32)
        UaKinds.kemRecordDigest(ua, 0, "0x" + "00".repeat(1600))
        compare(UaKinds.lastError, "UAKemVersion")
        UaKinds.kemRecordDigest(ua, 1, "0x" + "00".repeat(1599))
        compare(UaKinds.lastError, "UAKemKeyLength")
        UaKinds.kemRecordDigest(ua, 1, "0x" + "00".repeat(1601))
        compare(UaKinds.lastError, "UAKemKeyLength")
    }

    function test_structures() {
        for (const p of s.pop) {
            const portable = UaKinds.portablePopDigest(p.ua, p.pqzKeyHash, p.kemRecordHash)
            compare(portable, p.portablePopDigest)
            compare(UaKinds.registrationDigest(portable, p.pqzPopHash), p.registrationDigest)
        }
        for (const p of s.pqzReg) {
            compare(UaKinds.keyHashOf(0x0142, k.pqzKey), p.pqzKeyHash)
            compare(UaKinds.portablePopDigest(p.ua, p.pqzKeyHash, p.kemRecordHash), p.portablePopDigest)
            compare(UaKinds.uaMessage(0x0142, UaKinds.purposeTagV("pop", 2), p.portablePopDigest), p.pqzRegMessage)
            if (p.kemRecordHash !== "0x" + "00".repeat(32))
                continue  // an opaque label; the real records are in portable.json
            compare(UaKinds.pqzRegMessage(p.ua, k.pqzKey, 0, ""), p.pqzRegMessage)
            const h = JSON.parse(UaKinds.holderPopMessage(p.kind, p.ua, "0x", k.pqzKey, "0x" + "07".repeat(32), 0, ""))
            compare(h.pqzKeyHash, p.pqzKeyHash)
            compare(h.portablePopDigest, p.portablePopDigest)
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

    // metatx split T18: CTR-MTX-26 metaPayId / payLane and CTR-MTX-27 relayRef (EVM) against the forge-written vectors
    property var pm: vectors.load("../metatx/paymeta.json")
    property var rr: vectors.load("../metatx/relayref.json")

    function test_meta_pay_id_vectors() {
        compare(pm.length, 6)
        for (const r of pm) {
            compare(UaKinds.metaPayId(r.salt, r.meta), r.payId, r.name)
            compare(UaKinds.payLane(r.payId), r.payLane, r.name)
            compare(UaKinds.lastError, "")
        }
        compare(UaKinds.metaPayId("0x1234", "0x"), "")
        compare(UaKinds.lastError, "UAArgument")
        compare(UaKinds.payLane("0xzz"), "")
        compare(UaKinds.lastError, "UAArgument")
    }

    function test_relay_ref_matches_vector() {
        compare(rr.length, 3)
        for (const r of rr) {
            compare(UaKinds.relayRef(r.chainId, r.target, r.callData), r.ref, r.name)
            compare(UaKinds.payLane(r.ref), r.payLane, r.name)
        }
        compare(UaKinds.relayRef(7622, "0x" + "11".repeat(32), "0x"), "")
        compare(UaKinds.lastError, "UAArgument")
        compare(UaKinds.relayRef(-1, rr[0].target, "0x"), "")
        compare(UaKinds.lastError, "UAArgument")
    }

    // near-algorand T18: NEAR / Algorand MetaOp digest + relay-fee ref against the family vector files
    property var nv: vectors.load("../../near/vectors/near-vectors.json")
    property var av: vectors.load("../../algorand/vectors/algorand-vectors.json")

    function test_near_digest_and_relay_ref() {
        for (const r of nv.metaops.vectors) compare(UaKinds.nearDigest(r.encoding), r.digest, r.name)
        for (const r of nv.relayRefs) {
            compare(UaKinds.nearRelayRef(nv.network, r.targetBytes, r.call, r.salt), r.ref, r.name)
            compare(UaKinds.payLane(r.ref), r.lane, r.name)
        }
        compare(UaKinds.nearDigest("0xzz"), "")
        compare(UaKinds.lastError, "UAArgument")
        compare(UaKinds.nearRelayRef("0x1234", "0x", "0x", nv.relayRefs[0].salt), "")
        compare(UaKinds.lastError, "UAArgument")
    }

    function test_algorand_digest_and_relay_ref() {
        for (const r of av.metaops.vectors) compare(UaKinds.algorandDigest(r.encoding), r.digest, r.name)
        for (const r of av.relayRefs) {
            compare(UaKinds.algorandRelayRef(av.network, r.target, r.call, r.salt), r.ref, r.name)
            compare(UaKinds.payLane(r.ref), r.lane, r.name)
        }
        compare(UaKinds.algorandDigest("0x1"), "")
        compare(UaKinds.lastError, "UAArgument")
        compare(UaKinds.algorandRelayRef(av.network, "0x1234", "0x", av.relayRefs[0].salt), "")
        compare(UaKinds.lastError, "UAArgument")
    }

    function test_encode_msig() {
        const id = "0x" + "11".repeat(32)
        compare(UaKinds.encodeMsig(2, JSON.stringify([[256, id, 1], [257, id, 1]])),
                "0x00020002" + "0100" + "11".repeat(32) + "0001" + "0101" + "11".repeat(32) + "0001")
        compare(UaKinds.encodeMsig(1, "not json"), "")
        compare(UaKinds.lastError, "UAArgument")
    }
}
