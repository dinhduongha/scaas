// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
import QtQuick
import QtTest
import Scaas.Ua

// Mirrors clients/ua-rs/tests/vectors.rs against the shared vector files.
TestCase {
    name: "UaKinds"

    property var k: vectors.load("kinds.json")
    property var s: vectors.load("structures.json")
    property var d: vectors.load("id_display.json")

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

    // ua-mtx-merge spec §6, MD-9: every row of id_display.json, and a row for every kind of the table.
    function test_id_display_rows() {
        verify(d.rows.length > 0)
        for (const r of d.rows) {
            const got = UaKinds.idDisplay(r.id, r.kind)
            if (r.display) {
                compare(got, r.display.address ?? r.display.urn, r.name)
                compare(UaKinds.lastError, "", r.name)
            } else {
                compare(got, "", r.name)
                compare(UaKinds.lastError, r.error, r.name)
            }
        }
        for (const t of k.kinds) {
            const want = t.native ? (r => r.error === "UAKindNotDerived") : (r => !!(r.display && r.display.urn))
            verify(d.rows.some(r => r.kind === t.kind && want(r)), "no row for " + t.name)
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
        verify(pp.tags.KEM_RECORD_TAG === undefined)  // the raw record tags are legacy (TS-D3)
        compare(UaKinds.portableDomainSeparator(), pp.typed.domainSeparator)
        let withPqz = 0
        for (const r of pp.registrations) {
            const a = r.attrs
            const h = JSON.parse(UaKinds.holderPopMessage(r.kind, r.ua, r.keyData, a.pqzKey, r.pqzPop, a.kemPk))
            compare(UaKinds.lastError, "", r.name)
            compare(h.pqzKeyHash, r.pqzKeyHash, r.name)
            compare(h.pqzPopHash, a.pqzPopHash, r.name)
            compare(h.kemRecordHash, r.kemRecordHash, r.name)
            compare(h.portableRecordDigest, r.portableRecordDigest, r.name)
            compare(h.registrationDigest, r.registrationDigest, r.name)
            compare(h.message, r.popMessage, r.name)
            compare(h.memberDigest ?? "", r.memberDigest ?? "", r.name)
            compare(UaKinds.kemRecordHash(r.ua, 0, a.kemPk), r.kemRecordHash, r.name)  // the register key: version 0
            compare(UaKinds.portableRecordDigest(r.ua, r.kind, h.pqzKeyHash, h.kemRecordHash), r.portableRecordDigest, r.name)
            compare(UaKinds.registrationDigest(r.ua, r.kind, h.pqzKeyHash, h.kemRecordHash, h.pqzPopHash), r.registrationDigest, r.name)
            if (a.pqzKey !== "0x") {
                withPqz++
                compare(UaKinds.pqzRegMessage(r.kind, r.ua, a.pqzKey, a.kemPk), r.pqzRegMessage, r.name)
                // TS-D3: R_REG proves over the typed UAPortableRecord of the registering kind
                compare(UaKinds.uaMessage(0x0142, UaKinds.purposeTagV("pop", 2), r.portableRecordDigest), r.pqzRegMessage, r.name)
            }
        }
        verify(withPqz > 0)
        // mldsa87 (CTR-UA-39), fndsa1024 (CTR-UA-40): holders, read above and in test_set_key_args
        for (const k of [0x0134, 0x0135])
            compare(["registrations", "kemRecords", "pqzKeyRecords"].map(s => pp[s].filter(r => r.kind === k).length), [1, 3, 4], k)
        // hash-only proof path agrees with the proof bytes
        for (const r of pp.registrations) {
            const a = r.attrs
            if (a.pqzKey === "0x")
                continue
            const h = JSON.parse(UaKinds.holderPopMessageH(r.kind, r.ua, r.keyData, a.pqzKey, "0x", a.pqzPopHash, a.kemPk))
            compare(UaKinds.lastError, "", r.name)
            compare(h.message, r.popMessage, r.name)
        }
        // the portable.json negatives that are digest-layer rules (as ua-rs / ua-cs)
        let run = 0, sigLevel = 0
        for (const n of pp.negatives) {
            if (n.rule === "msig-minimal") continue // a registry rule over a full registration (msig minimal form)
            const m = n.mutation, set = m.set ?? {}
            const only = Object.keys(set).every(x => x.startsWith("attrs.") || x === "pqzPop")
            if ((n.entry === "register" || n.entry === "storePqzPop") && only) {
                const row = JSON.parse(JSON.stringify(pp.registrations.find(r => r.name === m.row)))
                for (const [key, v] of Object.entries(Object.assign({}, m.registerWith ?? {}, set))) {
                    if (key.startsWith("attrs.")) row.attrs[key.slice(6)] = v; else row[key] = v
                }
                const a = row.attrs
                const out = UaKinds.holderPopMessageH(row.kind, row.ua, row.keyData, a.pqzKey, row.pqzPop, a.pqzPopHash, a.kemPk)
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
                UaKinds.pqzKeyRecordMessage(holder.kind, ua, holder.keyData, rec.pqzKey, "0x", set.pqzPopHash ?? rec.pqzPopHash, holder.attrs.pqzKey !== "0x")
                compare(UaKinds.lastError, n.error, n.name)
                run++
            } else if (n.entry === "setKemKey" && n.name === "kem-record-of-other-ua") {
                const kr = pp.kemRecords.find(r => r.id === m.row)
                const t = pp.registrations.find(r => r.ua === set.ua)
                const d = UaKinds.kemRecordDigest(set.ua, Number(kr.version), kr.kemPk)
                verify(UaKinds.uaMessage(t.kind, UaKinds.purposeTag("kem"), d) !== kr.message, n.name)
                run++
            } else if (n.name === "record-kind-mismatch") {
                // the typed record binds `kind`: the same UA and attributes under another kind is another message
                const row = pp.registrations.find(r => r.name === m.row), z = "0x" + "00".repeat(32)
                const d = UaKinds.registrationDigest(row.ua, m.otherKind, z, UaKinds.kemRecordHash(row.ua, 0, "0x"), z)
                verify(UaKinds.uaMessage(row.kind, UaKinds.purposeTagV("pop", 2), d) !== row.popMessage, n.name)
                run++
            } else if (n.name === "kem-record-as-registration") {
                // the row's own typed KEM record is not its registration (struct type)
                const row = pp.registrations.find(r => r.name === m.row)
                verify(pp.kemRecords.find(r => r.ua === row.ua).digest !== row.registrationDigest, n.name)
                run++
            } else {
                sigLevel++  // signatures / native members: verified by the signature vectors
            }
        }
        compare(run + sigLevel + 1, pp.negatives.length) // + the skipped msig-minimal row
        verify(run > 0 && sigLevel > 0)
        // refusals
        const proof = "0x" + "07".repeat(32), ua = "0x" + "01".repeat(32)
        for (const bad of [0x0101, 0x0133]) {  // single-key non-holders refuse a PQZ key (on every pqzReg row's UA)
            for (const p of s.pqzReg) {
                UaKinds.holderPopMessage(bad, p.ua, "0x", k.pqzKey, proof, "")
                compare(UaKinds.lastError, "UAPqzHolder")
            }
        }
        UaKinds.holderPopMessage(0x0130, ua, "0x", k.pqzKey, "0x", "")
        compare(UaKinds.lastError, "UAPqzPopHash")  // a PQZ key without its proof
        UaKinds.holderPopMessage(0x0120, ua, "0x000200", k.pqzKey, proof, "")
        compare(UaKinds.lastError, "UAKeyData")
        UaKinds.holderPopMessage(0x0120, ua, "0x", k.pqzKey, proof, "")
        compare(UaKinds.lastError, "UAPqzHolder")
        UaKinds.holderPopMessage(0x0101, ua, "0x", "0x", "0x", "0x01" + "00".repeat(1600))
        compare(UaKinds.lastError, "UAKemHolder")
        UaKinds.holderPopMessage(0x0130, ua, "0x", "0x", "0x", "0x00" + "00".repeat(1600))
        compare(UaKinds.lastError, "UAKemScheme")  // version 0 with scheme 0
        // a proof hash of the wrong length is UAPqzPopHash, as in every other package (m-C4)
        UaKinds.holderPopMessageH(0x0130, ua, "0x", k.pqzKey, "0x", "0x" + "07".repeat(31), "")
        compare(UaKinds.lastError, "UAPqzPopHash")
        UaKinds.pqzKeyRecordMessage(0x0130, ua, "0x", k.pqzKey, "0x", "0x" + "07".repeat(31), false)
        compare(UaKinds.lastError, "UAPqzPopHash")
        // keccak256("evm:1099511627783"), as ua-py / ua-go
        compare(UaKinds.chainKeyHash(1099511627783), "0x6e45d591a544f53396f6e86d49f5809196c5725f9d99dbd2ca97f9925c7ce950")
    }

    function test_membershipRows() {
        const rows = vectors.load("portable.json").memberships
        compare(rows.length, 6)
        for (const r of rows) {
            compare(UaKinds.membershipDigest(r.ua, r.member), r.digest, r.name)
            compare(UaKinds.uaMessage(0x0120, UaKinds.purposeTag("membership"), r.digest), r.message, r.name)
            compare(UaKinds.memberDigest(r.ua, r.message), r.memberDigest, r.name)
        }
    }

    function test_portablePurposes() {
        const pp = vectors.load("portable.json")
        verify(UaKinds.isPortablePurpose(pp.tags.PURPOSE_POP_V2.hash) && UaKinds.isPortablePurpose(pp.tags.PURPOSE_KEM.hash)
               && UaKinds.isPortablePurpose(pp.tags.PURPOSE_PQZ_KEY.hash))
        verify(!UaKinds.isPortablePurpose(UaKinds.purposeTag("metatx")) && !UaKinds.isPortablePurpose(UaKinds.purposeTag("pop")))
        compare(UaKinds.lastError, "")
        verify(!UaKinds.isPortablePurpose("0x" + "00".repeat(31)))
        compare(UaKinds.lastError, "UAArgument")
        UaKinds.portableRecordDigest("0x" + "00".repeat(31), 0x0130, "0x" + "00".repeat(32), "0x" + "00".repeat(32))
        compare(UaKinds.lastError, "UAArgument")
    }

    function test_pqzKeyRecord() {
        const pp = vectors.load("portable.json")
        let msigRows = 0
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
                compare(g.memberDigest ?? "", r.memberDigest ?? "", r.name)
                if (r.kind === 0x0120) {
                    compare(g.memberDigest, UaKinds.memberDigest(r.ua, g.message), r.name)
                    msigRows++
                }
            }
            UaKinds.pqzKeyRecordMessage(r.kind, r.ua, reg.keyData, r.pqzKey, "0x", r.pqzPopHash, true)
            compare(UaKinds.lastError, "UAPqzKeySet", r.name)
            compare(UaKinds.pqzKeyDigest(r.ua, r.pqzKeyHash), r.pqzKeyDigest, r.name)
            compare(UaKinds.pqzKeyRecordDigest(r.ua, r.pqzKeyHash, r.pqzPopHash), r.recordDigest, r.name)
        }
        verify(msigRows > 0)
    }

    function test_kemRecord() {
        const pp = vectors.load("portable.json")
        for (const r of pp.kemRecords) {
            const d = UaKinds.kemRecordDigest(r.ua, Number(r.version), r.kemPk)
            compare(d, r.digest, r.id)
            compare(UaKinds.kemRecordHash(r.ua, Number(r.version), r.kemPk), r.structHash, r.id)
            compare(UaKinds.uaMessage(r.kind, UaKinds.purposeTag("kem"), d), r.message, r.id)
            compare(UaKinds.kemRecordMessage(r.kind, r.ua, Number(r.version), r.kemPk), r.message, r.id)
            if (r.kind === 0x0120)
                compare(UaKinds.memberDigest(r.ua, r.message), r.memberDigest, r.id)
        }
        const ua = "0x" + "01".repeat(32)
        const kem = (n, scheme = "01") => "0x" + scheme + "00".repeat(n - 1) // scheme byte, zeros, n bytes in all
        UaKinds.kemRecordDigest(ua, 0, kem(1601))
        compare(UaKinds.lastError, "UAKemVersion")
        // owner 2026-10-31: version 0 with a key is the register key's record (scheme != 0), never a setKemKey record
        verify(UaKinds.kemRecordHash(ua, 0, kem(1601)) !== UaKinds.kemRecordHash(ua, 0, "0x"))
        compare(UaKinds.lastError, "")
        UaKinds.kemRecordHash(ua, 0, kem(1601, "00"))
        compare(UaKinds.lastError, "UAKemScheme")
        UaKinds.kemRecordDigest(ua, 1, kem(1600))
        compare(UaKinds.lastError, "UAKemKeyLength")
        UaKinds.kemRecordDigest(ua, 1, kem(1602))
        compare(UaKinds.lastError, "UAKemKeyLength")
        UaKinds.kemRecordDigest(ua, 1, "0x")
        compare(UaKinds.lastError, "UAKemKeyLength")
        for (const scheme of ["00", "02", "ff"]) {
            UaKinds.kemRecordDigest(ua, 1, kem(1601, scheme))
            compare(UaKinds.lastError, "UAKemScheme", scheme)
        }
        // known answer at 2^53, the largest version a QML number carries exactly (ua-rs / ua-py pin 2^64 - 1)
        compare(UaKinds.kemRecordDigest(ua, 9007199254740992, kem(1601)), "0x04a0150e24a83fa4dbc9f760b7f649f939bcb62cb4ddd3a9f56f7d2e3d990482")
        UaKinds.kemRecordDigest(ua, 9007199254740994, kem(1601))
        compare(UaKinds.lastError, "UAArgument")
    }

    function test_structures() {
        for (const p of s.pop) {
            compare(UaKinds.portableRecordDigest(p.ua, p.kind, p.pqzKeyHash, p.kemRecordHash), p.portableRecordDigest)
            compare(UaKinds.registrationDigest(p.ua, p.kind, p.pqzKeyHash, p.kemRecordHash, p.pqzPopHash), p.registrationDigest)
        }
        for (const p of s.pqzReg) {
            compare(UaKinds.keyHashOf(0x0142, k.pqzKey), p.pqzKeyHash)
            compare(UaKinds.portableRecordDigest(p.ua, p.kind, p.pqzKeyHash, p.kemRecordHash), p.portableRecordDigest)
            compare(UaKinds.uaMessage(0x0142, UaKinds.purposeTagV("pop", 2), p.portableRecordDigest), p.pqzRegMessage)
            if (p.kemRecordHash !== UaKinds.kemRecordHash(p.ua, 0, "0x"))
                continue  // an opaque label; the real records are in portable.json
            compare(UaKinds.pqzRegMessage(p.kind, p.ua, k.pqzKey, ""), p.pqzRegMessage)
            const h = JSON.parse(UaKinds.holderPopMessage(p.kind, p.ua, "0x", k.pqzKey, "0x" + "07".repeat(32), ""))
            compare(h.pqzKeyHash, p.pqzKeyHash)
            compare(h.portableRecordDigest, p.portableRecordDigest)
        }
        for (const p of s.pqzMsig) {
            compare(UaKinds.msigPqzEligible(p.keyData), p.eligible, p.reason)
            compare(UaKinds.portableRecordDigest(p.ua, 0x0120, p.eligible ? k.pqzKeyHash : "0x" + "00".repeat(32), UaKinds.kemRecordHash(p.ua, 0, "0x")),
                    p.portableRecordDigest, p.reason)
        }
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
    property var pm: vectors.load("../metatx/legacy/ua-mtx-merge/paymeta.json")
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

    // clientkeys registrationArgs' input of a registration row; an msig's pop is its typed member list
    function regInput(r) {
        return { kind: r.kind, keyData: r.keyData, pqzKey: r.attrs.pqzKey, pqzPopHash: r.attrs.pqzPopHash, pqzPop: r.pqzPop,
                 kemPk: r.attrs.kemPk, pop: r.args.pop }
    }
    function regArgs(i) {
        const o = UaKinds.registrationArgs(JSON.stringify(i))
        compare(UaKinds.lastError, "")
        return JSON.parse(o)
    }

    // the With forms with inner ({id: keyData}, the JSON calls' form): msig-nested-pq's eligibility and holder record, every eligibility
    // row and every nested PQZ key record reproduce; without inner they stay UAMemberUnknown, so does a third level. Every memberships
    // row's stored bytes turn back into its slot through replayedMemberSig
    function test_nested_inner() {
        const n = vectors.load("nested.json")
        const inner = {}
        for (const r of n.registrations) if (r.kind === 0x0120) inner[r.ua] = r.keyData
        const all = JSON.stringify(inner)
        const holders = n.registrations.concat(n.afterAcceptance).filter(r => r.attrs.kemPk !== "0x" || r.attrs.pqzKey !== "0x")
        compare(holders.map(r => r.name), ["msig-nested-pq"])
        for (const r of holders) {
            verify(UaKinds.msigPqzEligibleWith(r.keyData, all), r.name)
            compare(UaKinds.lastError, "", r.name)
            verify(!UaKinds.msigPqzEligible(r.keyData))
            compare(UaKinds.lastError, "UAMemberUnknown", r.name)
            const h = JSON.parse(UaKinds.holderPopMessageWith(r.kind, r.ua, r.keyData, "0x", "0x", "0x", r.attrs.kemPk, all))
            compare([h.kemRecordHash, h.portableRecordDigest, h.registrationDigest, h.message, h.memberDigest],
                    [r.kemRecordHash, r.portableRecordDigest, r.registrationDigest, r.popMessage, r.memberDigest], r.name)
            compare(UaKinds.holderPopMessageWith(r.kind, r.ua, r.keyData, "0x", "0x", "0x", r.attrs.kemPk, ""), "")
            compare(UaKinds.lastError, "UAMemberUnknown", r.name)
        }
        for (const r of n.eligibility) {
            compare(UaKinds.msigPqzEligibleWith(r.keyData, JSON.stringify(r.inner)), r.eligible, r.reason)
            compare(UaKinds.lastError, "", r.reason)
            for (const none of ["", "null", "{}"]) {
                verify(!UaKinds.msigPqzEligibleWith(r.keyData, none))
                compare(UaKinds.lastError, "UAMemberUnknown", r.reason)
            }
        }
        const third = n.structures[0], pq = holders[0].keyData, t = {}
        t[third.member] = pq
        verify(!UaKinds.msigPqzEligibleWith(third.keyData, JSON.stringify(t)))
        compare(UaKinds.lastError, "UAMemberUnknown", "a third level")
        for (const bad of ["not json", "[]", JSON.stringify({"0x01": "0x"}), " ".repeat(65537)]) {
            verify(!UaKinds.msigPqzEligibleWith(pq, bad))
            compare(UaKinds.lastError, "UAArgument", bad.slice(0, 12))
        }
        compare(n.pqzKeyRecords.length, 4)
        for (const r of n.pqzKeyRecords) {
            const g = JSON.parse(UaKinds.pqzKeyRecordMessageWith(r.kind, r.ua, inner[r.ua], r.pqzKey, "0x", r.pqzPopHash, false, all))
            compare([g.pqzKeyHash, g.pqzPopHash, g.pqzKeyDigest, g.recordDigest, g.message, g.pqzRegMessage, g.memberDigest],
                    [r.pqzKeyHash, r.pqzPopHash, r.pqzKeyDigest, r.recordDigest, r.message, r.pqzRegMessage, r.memberDigest], r.name)
            compare(UaKinds.pqzKeyRecordMessageWith(r.kind, r.ua, inner[r.ua], r.pqzKey, "0x", r.pqzPopHash, false, ""), "")
            compare(UaKinds.lastError, "UAMemberUnknown", r.name)
        }
        compare(n.memberships.length, 4)
        for (const m of n.memberships) {
            const d = n.registrations.find(r => r.ua === m.ua).keyData
            compare(JSON.parse(UaKinds.replayedMemberSig(d, m.index, m.stored)), {index: m.index, members: m.members, sig: m.sig}, m.name)
            compare(UaKinds.replayedMemberSig(d, 16, m.stored), "")
            compare(UaKinds.lastError, "UAUnauthorized", m.name)
            if (m.members.length > 0) {
                compare(UaKinds.replayedMemberSig(d, m.index, m.stored + "00"), "")
                compare(UaKinds.lastError, "UAUnauthorized", m.name + ": not canonical")
            }
        }
    }

    // abi.encode(InnerSig[]) of a typed list [{index, sig}], as hex: the bytes an msig member's UAMemberSig carries
    function encodeInnerSigs(list) {
        const w = v => ("0".repeat(64) + v.toString(16)).slice(-64)
        let head = w(0x20) + w(list.length), tail = ""
        for (const x of list) {
            const s = x.sig.slice(2)
            head += w(32 * list.length + tail.length / 2)
            tail += w(x.index) + w(0x40) + w(s.length / 2) + s + "0".repeat((64 - s.length % 64) % 64)
        }
        return "0x" + head + tail
    }

    // owner 2026-11-03: memberSigHashOf(ua, index) is keccak256 of the bytes the slot's UAMemberSig carries: its sig, or an msig member's
    // abi.encode(InnerSig[]). Every msig registration row's memberSigHashes (portable.json, its negative, nested.json), and every memberships
    // row's storedHash = keccak256(stored), stored being that slot's bytes
    function test_member_sig_hashes() {
        const pp = vectors.load("portable.json"), n = vectors.load("nested.json")
        const rows = pp.registrations.concat(pp.negatives.filter(x => x.registration).map(x => x.registration), n.registrations, n.afterAcceptance)
            .filter(r => r.kind === 0x0120)
        let slots = 0, inner = 0
        for (const r of rows) {
            compare(r.memberSigHashes.length, r.args.pop.length, r.name)
            r.args.pop.forEach((s, i) => {
                const msig = s.members.length > 0
                inner += msig ? 1 : 0
                ++slots
                compare([r.memberSigHashes[i].index, r.memberSigHashes[i].hash],
                        [s.index, UaKinds.keccak256(msig ? encodeInnerSigs(s.members) : s.sig)], r.name + " slot " + i)
            })
        }
        compare([rows.length, slots, inner], [19, 30, 7], "msig rows, slots, msig-member slots")
        compare(n.memberships.length, 4)
        for (const m of n.memberships) {
            compare(UaKinds.keccak256(m.stored), m.storedHash, m.name)
            compare(m.members.length > 0 ? encodeInnerSigs(m.members) : m.sig, m.stored, m.name + ": the encoder's control")
        }
        compare(UaKinds.keccak256("0x"), "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        compare(UaKinds.lastError, "")
        compare(UaKinds.keccak256("0x0"), "")
        compare(UaKinds.lastError, "UAArgument")
    }

    // nested msig (nested.json): the digest chain from the low-level calls, the JSON calls with `inner`. Key data alone refuses an msig member by
    // name, so holderPopMessage and pqzKeyRecordMessage stop there on a record that needs its inner keys; their `With` forms take `inner`
    // (test_nested_inner). This API verifies no signature
    function test_nested_rows() {
        const n = vectors.load("nested.json")
        const inner = {}
        for (const r of n.registrations) if (r.kind === 0x0120) inner[r.ua] = r.keyData
        const zero = "0x" + "00".repeat(32), popTag = UaKinds.purposeTagV("pop", 2), memberTag = UaKinds.purposeTag("member")
        const rows = n.registrations.concat(n.afterAcceptance)
        compare(rows.length, 17)
        for (const r of rows) {
            compare(UaKinds.uaOf(r.kind, r.keyData), r.ua, r.name)
            const kem = UaKinds.kemRecordHash(r.ua, 0, r.attrs.kemPk)
            const rd = UaKinds.registrationDigest(r.ua, r.kind, zero, kem, zero), msg = UaKinds.uaMessage(r.kind, popTag, rd)
            compare([kem, UaKinds.portableRecordDigest(r.ua, r.kind, zero, kem), rd, msg],
                    [r.kemRecordHash, r.portableRecordDigest, r.registrationDigest, r.popMessage], r.name)
            const i = regInput(r)
            i.kemCommit = false
            i.inner = inner
            compare(regArgs(i).args, r.args, r.name)
            if (r.kemCommit) {
                i.kemCommit = true
                const c = regArgs(i)
                compare([c.args, c.kemFill], [r.kemCommit.register, r.kemCommit.fill], r.name)
                UaKinds.holderPopMessage(r.kind, r.ua, r.keyData, "0x", "0x", r.attrs.kemPk)
                compare(UaKinds.lastError, "UAMemberUnknown", r.name)
            }
            if (r.kind !== 0x0120) continue
            const md = UaKinds.memberDigest(r.ua, msg)
            compare(md, r.memberDigest, r.name)
            for (const x of r.innerDigests || [])
                compare(UaKinds.memberDigest(x.inner, UaKinds.uaMessage(0x0120, memberTag, md)), x.memberDigest, r.name)
        }
        compare([n.kemRecords.length, n.pqzKeyRecords.length], [1, 4])
        for (const r of n.kemRecords) {
            const m = UaKinds.kemRecordMessage(r.kind, r.ua, r.version, r.kemPk)
            compare([UaKinds.kemRecordDigest(r.ua, r.version, r.kemPk), m, UaKinds.memberDigest(r.ua, m)], [r.digest, r.message, r.memberDigest], r.id)
            compare(JSON.parse(UaKinds.setKemKeyArgs(JSON.stringify({ ua: r.ua, version: r.version, kemPk: r.kemPk, sig: recordSig(r) }))), r.args, r.id)
        }
        for (const r of n.pqzKeyRecords) {
            const tag = UaKinds.purposeTag("pqz-key"), kd = UaKinds.pqzKeyDigest(r.ua, r.pqzKeyHash)
            const rd = UaKinds.pqzKeyRecordDigest(r.ua, r.pqzKeyHash, r.pqzPopHash), m = UaKinds.uaMessage(r.kind, tag, rd)
            compare([kd, rd, m, UaKinds.uaMessage(0x0142, tag, kd), UaKinds.memberDigest(r.ua, m)],
                    [r.pqzKeyDigest, r.recordDigest, r.message, r.pqzRegMessage, r.memberDigest], r.name)
            compare(JSON.parse(UaKinds.setPqzKeyArgs(JSON.stringify({ ua: r.ua, pqzKey: r.pqzKey, pqzPopHash: r.pqzPopHash, sig: recordSig(r) }))), r.args, r.name)
            UaKinds.pqzKeyRecordMessage(r.kind, r.ua, inner[r.ua], r.pqzKey, "0x", r.pqzPopHash, false)
            compare(UaKinds.lastError, "UAMemberUnknown", r.name)
        }
        compare(n.memberships.length, 4)
        for (const m of n.memberships) {
            const d = UaKinds.membershipDigest(m.ua, m.member), msg = UaKinds.uaMessage(0x0120, UaKinds.purposeTag("membership"), d)
            compare([d, msg, UaKinds.memberDigest(m.ua, msg)], [m.digest, m.message, m.memberDigest], m.name)
        }
        compare(n.authorizations.length, 5)
        const k = n.kemRecords[0]
        for (const a of n.authorizations) {
            compare(UaKinds.memberDigest(a.ua, UaKinds.uaMessage(0x0120, a.purposeTag, a.digest)), a.memberDigest, a.name)
            compare(JSON.parse(UaKinds.setKemKeyArgs(JSON.stringify({ ua: k.ua, version: k.version, kemPk: k.kemPk, sig: a.uaSig }))).sig, a.uaSig, a.name)
        }
        // the builder's own refusal is the minimal rule at both levels; the others are the registry's, on the signatures
        const minimal = ["inner-below-threshold", "inner-index-past-the-members", "inner-unsorted", "inner-not-minimal", "outer-not-minimal"]
        compare(n.negatives.length, 13)
        for (const x of n.negatives) {
            const i = regInput(n.registrations.concat(n.afterAcceptance).find((r) => r.name === x.row))
            i.kemCommit = false
            i.inner = inner
            i.pop = x.popTyped
            if (minimal.includes(x.name)) {
                compare(UaKinds.registrationArgs(JSON.stringify(i)), "", x.name)
                compare(UaKinds.lastError, x.error, x.name)
            } else {
                compare(regArgs(i).args.pop, x.popTyped, x.name)
            }
        }
        compare(n.structures.length, 2)
        for (const s of n.structures) {
            compare(UaKinds.uaOf(0x0120, s.keyData), s.ua, s.name)
            compare(UaKinds.msigPqzEligible(s.keyData), false, s.name)
            compare(UaKinds.lastError, s.error, s.name)
        }
        for (const r of n.eligibility) {
            compare(UaKinds.msigPqzEligible(r.keyData), false, r.reason)
            compare(UaKinds.lastError, "UAMemberUnknown", r.reason)
        }
    }

    function test_registration_args() {
        const pp = vectors.load("portable.json")
        let commits = 0
        for (const r of pp.registrations) {
            const a = regArgs(Object.assign(regInput(r), { kemCommit: false }))
            compare(a.args, r.args, r.name)
            compare(a.kemFill, null, r.name)
            compare(a.kemFillCalldataLength, null, r.name)
            compare(regArgs(regInput(r)).args, r.args, r.name)  // under the limit: the full key
            if (r.attrs.kemPk === "0x") {
                verify(r.kemCommit === undefined, r.name)
                continue
            }
            const c = regArgs(Object.assign(regInput(r), { kemCommit: true }))
            compare(c.args, r.kemCommit.register, r.name)
            compare(c.kemFill, r.kemCommit.fill, r.name)
            compare(c.kemFillCalldataLength, 2020, r.name)
            commits++
        }
        compare(commits, pp.registrations.filter(r => r.kemCommit !== undefined).length)
        verify(commits > 0)
        const typed = { 256: ["registerWebAuthn", 580], 272: ["registerMuSig2", 1124], 274: ["registerMuSig2", 1124],
                        273: ["registerFrost", 2308], 275: ["registerFrost", 2308] }
        const rows = k.valid.filter(v => typed[v.kind] !== undefined)
        compare(rows.length, 6)
        for (const v of rows) {  // no attributes, a 32-byte pop (cast 1.8.5)
            const a = regArgs({ kind: v.kind, keyData: v.keyData, pop: "0x" + "00".repeat(32) })
            compare([a.args.entry, a.calldataLength], typed[v.kind], v.name)
        }
        compare(regArgs({ kind: 257, keyData: k.valid[1].keyData }).args.entry, "register")
        // the hash commit only over 261,909 B (PQZH n2560-kmax16384's sizes; ua-rs registration_hash_commit_when_over_limit)
        const x = { kind: 0x0131, keyData: "0x" + "5a".repeat(1952), pqzKey: "0x" + "5a".repeat(20480), pqzPop: "0x" + "5a".repeat(234238),
                    kemPk: "0x01" + "5a".repeat(1600), pop: "0x" + "5a".repeat(3309) }
        compare(regArgs(Object.assign({}, x, { kemCommit: false })).calldataLength, 262116)
        const auto = regArgs(x)
        compare([auto.calldataLength, auto.kemFillCalldataLength, auto.kemFill.version], [260548, 2020, 0])
        for (const [bad, code] of [["not json", "UAArgument"], ['{"kind": 65536}', "UAArgument"],
                                   ['{"kind": 257, "keyData": "0xzz"}', "UAArgument"],
                                   ['{"kind": 288, "keyData": "0x00020000", "pop": "0x"}', "UAArgument"],
                                   ['{"kind": 288, "keyData": "0x000200"}', "UAKeyData"],
                                   ['{"kind": 305, "kemPk": "0x0101"}', "UAKemKeyLength"],
                                   ['{"kind": 305, "pqzKey": "0x01", "pqzPopHash": "0x01", "pqzPop": "0x01"}', "UAPqzPopHash"]]) {
            compare(UaKinds.registrationArgs(bad), "", bad)
            compare(UaKinds.lastError, code, bad)
        }
    }

    // a record row's UASig: its sig, an msig's as the typed member list; absent fields are empty
    function recordSig(r) {
        return r.kind === 0x0120 ? { members: r.args.sig.members } : { signature: r.sig }
    }

    function test_set_key_args() {
        const pp = vectors.load("portable.json")
        compare(pp.kemRecords.length, 15)  // + v1-v3 of mldsa87, fndsa1024
        for (const k of pp.kemRecords) {
            const o = UaKinds.setKemKeyArgs(JSON.stringify({ ua: k.ua, version: k.version, kemPk: k.kemPk, sig: recordSig(k) }))
            compare(UaKinds.lastError, "", k.id)
            compare(JSON.parse(o), k.args, k.id)
        }
        compare(pp.pqzKeyRecords.length, 16)  // + mldsa87, fndsa1024 at the four sets
        for (const r of pp.pqzKeyRecords) {
            const o = UaKinds.setPqzKeyArgs(JSON.stringify({ ua: r.ua, pqzKey: r.pqzKey, pqzPopHash: r.pqzPopHash, sig: recordSig(r) }))
            compare(UaKinds.lastError, "", r.name)
            compare(JSON.parse(o), r.args, r.name)
        }
        const ua = "0x" + "11".repeat(32)
        for (const [bad, code] of [["not json", "UAArgument"],
                                   ['{"ua": "0x11", "version": 1}', "UAArgument"],
                                   [JSON.stringify({ ua }), "UAArgument"],
                                   [JSON.stringify({ ua, version: 1, kemPk: "0x0101" }), "UAKemKeyLength"]]) {
            compare(UaKinds.setKemKeyArgs(bad), "", bad)
            compare(UaKinds.lastError, code, bad)
        }
        for (const [bad, code] of [["not json", "UAArgument"],
                                   [JSON.stringify({ ua, pqzPopHash: "0x01" }), "UAPqzPopHash"],
                                   [JSON.stringify({ ua, pqzPopHash: ua, sig: "0x01" }), "UAArgument"]]) {
            compare(UaKinds.setPqzKeyArgs(bad), "", bad)
            compare(UaKinds.lastError, code, bad)
        }
    }

    function test_encode_msig() {
        const id = "0x" + "11".repeat(32)
        compare(UaKinds.encodeMsig(2, JSON.stringify([[256, id, 1], [257, id, 1]])),
                "0x00020002" + "0100" + "11".repeat(32) + "0001" + "0101" + "11".repeat(32) + "0001")
        compare(UaKinds.encodeMsig(1, "not json"), "")
        compare(UaKinds.lastError, "UAArgument")
    }

    // governance T14: governanceBit against governance_bits.json on disk, every row; past bit 22 "" and UAArgument
    function test_governance_bits_rows() {
        const v = vectors.load("../governance/governance_bits.json")
        compare(v.bits.length, 23)
        for (const r of v.bits) {
            compare(JSON.parse(UaKinds.governanceBit(r.bit)), r, "bit " + r.bit)
            compare(UaKinds.lastError, "")
        }
        for (const bit of [23, 127, 128, 255, 256, -1]) {
            compare(UaKinds.governanceBit(bit), "", bit)
            compare(UaKinds.lastError, "UAArgument", bit)
        }
    }
}
