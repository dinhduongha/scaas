// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
import QtQuick
import QtTest
import Scaas.Ua

// ua-rs-sign T13b: the QML singleton UaWallet gets public data, `seal` to a public key and sign requests by handle id; no
// decaps, no raw export, no handle. The wallet is opened on the C++ side (ua-cxx, `fixture` in tst_ua.cpp), which hands key
// handles to QML only by id (scaas::ua::registerKey).
TestCase {
    name: "UaWallet"

    property var keys: vectors.load("keys.json")
    property var sign: vectors.load("sign.json")
    property var kem: vectors.load("kem.json")
    readonly property var deterministic: [0x0101, 0x0102, 0x0106, 0x0107, 0x0108]

    function cleanup() { fixture.restoreReported() }

    function test_load_refuses_wrong_abi_or_features() {
        const id = fixture.key("pq_kat", 0x0102, 0, 0)
        verify(UaWallet.keyData(id).length > 2)
        compare(UaWallet.lastError, "")
        fixture.reportAbi(5)  // an older core
        compare(UaWallet.keyData(id), "")
        compare(UaWallet.lastError, "UAAbiMismatch")
        compare(UaWallet.signUa(id, "0x" + "00".repeat(32), "0x" + "00".repeat(32)), "")
        compare(UaWallet.lastError, "UAAbiMismatch")
        compare(UaWallet.seal(kem.keys[0].kemPk, "scaas/backup/v1", "0x", "0x01"), "")
        compare(UaWallet.lastError, "UAAbiMismatch")
        fixture.restoreReported()
        fixture.reportFeaturesWithoutPqz()
        compare(UaWallet.keyData(id), "")
        compare(UaWallet.lastError, "UAAbiMismatch")
        fixture.restoreReported()
        fixture.reportVectorsBuild()  // Codex C1 (T15c2): a test build is refused at load
        compare(UaWallet.keyData(id), "")
        compare(UaWallet.lastError, "UAAbiMismatch")
        fixture.restoreReported()
        compare(fixture.linkedCoreIsATestBuild(), false)
        verify(UaWallet.keyData(id).length > 2)
        compare(UaWallet.lastError, "")
    }

    function test_secret_buffer_wiped_after_call() {
        // the C++ side (ua-cxx in this build) wipes the caller's mnemonic and passphrase, on success and on a refusal
        compare(fixture.mnemonicWipedAfterOpen(), true)
    }

    // ARCH-POS-13 (Fable P2-5, T15c2): UaWallet wraps neither facade (no `zetherKey`, `pqzKey`, `call` below), so ua-qt has no
    // Zether or PQZ call path and no "raw command refused" assertion of its own; ua-cxx's tests hold them.
    function test_no_decaps_no_raw_export_no_handle() {
        for (const n of ["decaps", "open", "openContainer", "kemKey", "exportPqzLeafRaw", "signDigestRaw", "signTypedAny",
                         "registerKey", "releaseKey", "uaKey", "nativeKey", "fromMnemonic", "openVault", "reveal", "take",
                         "zetherKey", "pqzKey", "call", "openBalanceCache"])
            compare(UaWallet[n], undefined, n)
        for (const n of ["keyData", "ua", "address", "network", "kind", "isUa", "signUa", "signMember", "signTyped",
                         "signTransaction", "signKeyProof", "uaSig", "seal"])
            compare(typeof UaWallet[n], "function", n)
    }

    function test_public_fields_by_id() {  // not "*_data": QtQuickTest reads that as a data function
        let n = 0
        for (const r of keys.ua) {
            if (r.mnemonic !== "pq_kat" || r.index !== 0 || r.account !== 0 || r.kind === 0x0132 || r.kind === 0x0135) continue
            const id = fixture.key(r.mnemonic, r.kind, r.account, r.index)
            compare(UaWallet.keyData(id), r.keyData, r.name)
            compare(UaWallet.isUa(id), true, r.name)
            compare(UaWallet.kind(id), r.kind, r.name)
            if (r.ua !== null && r.kind !== 0x0110 && r.kind !== 0x0112) compare(UaWallet.ua(id), r.ua, r.name)
            n++
        }
        compare(n, 14, "every UA kind of pq_kat at (0, 0) but the two Falcon kinds")
        let m = 0
        for (const r of keys.native) {
            if (r.mnemonic !== "pq_kat" || r.index !== 0 || r.coinType !== null) continue
            m++
            const id = fixture.native(r.mnemonic, r.network, r.index)
            compare(UaWallet.keyData(id), "0x" + r.publicKey, r.network)
            compare(UaWallet.network(id), r.network)
            compare(UaWallet.isUa(id), false)
            if (r.address !== null) compare(UaWallet.address(id), r.address, r.network)
        }
        compare(m, 9, "every network")
        compare(UaWallet.keyData(987654), "")
        compare(UaWallet.lastError, "UAArgument")
    }

    function test_sign_by_handle_id() {
        let exact = 0
        for (const r of sign.ua) {
            if (deterministic.indexOf(r.kind) < 0) continue
            const id = fixture.key(r.mnemonic, r.kind, r.account, r.index)
            compare(UaWallet.signUa(id, r.purposeTag, r.digest), r.signature, r.name)
            compare(UaWallet.lastError, "", r.name)
            exact++
        }
        verify(exact >= 10)
        for (const r of sign.member) {
            const id = fixture.key(r.mnemonic, r.kind, r.account, r.index)
            const got = UaWallet.signMember(id, r.structureUa, r.structureUaMsg)
            if (deterministic.indexOf(r.kind) >= 0) compare(got, r.signature, r.name)
            else compare(got.length, r.signature.length, r.name)
        }
        const evm = fixture.native("pq_kat", "evm", 0)
        let signed = 0, refused = 0
        for (const r of sign.policy) {
            const got = UaWallet.signTyped(evm, JSON.stringify(r.td), JSON.stringify(r.expect))
            if (r.refused !== undefined) {
                compare(got, "", r.id)
                compare(UaWallet.lastError, "UAPolicyRefused", r.id)
                refused++
            } else {
                compare(got, fixture.rawSignature(evm, r.digest), r.id)
                signed++
            }
        }
        compare([signed, refused], [10, 14])
        for (const r of sign.tx.rows) {
            const id = fixture.native(r.signer.mnemonic, r.signer.network, r.signer.index)
            compare(UaWallet.signTransaction(id, JSON.stringify(r.tx)), r.raw, "type " + r.tx.type)
        }
        for (const r of sign.tx.refusals) {
            compare(UaWallet.signTransaction(evm, JSON.stringify(r.tx)), "", r.id)
            compare(UaWallet.lastError, "UAArgument", r.id)
        }
        compare(UaWallet.signKeyProof(evm, "0x" + "63".repeat(9)).length, 2 + 130)
        compare(UaWallet.signUa(evm, "0x" + "00".repeat(32), "0x" + "00".repeat(32)), "")
        compare(UaWallet.lastError, "UAArgument", "sign_ua with a native key")
    }

    function test_uasig_msig_by_handle_ids() {
        let built = 0, refused = 0
        for (const r of sign.msig) {
            const ids = []
            const pos = x => { ids.push(fixture.key(x.key.mnemonic, x.key.kind, x.key.account, x.key.index)); return ids.length - 1 }
            const slots = r.slots.map(s => s.members !== undefined
                ? {index: s.index, members: s.members.map(x => ({index: x.index, key: pos(x)}))}
                : {index: s.index, key: pos(s)})
            const m = {keyData: r.keyData, slots: slots}
            if (r.inner !== undefined) m.inner = r.inner
            const got = UaWallet.uaSig(JSON.stringify({purpose: r.purposeTag, digest: r.digest, msig: m}), JSON.stringify(ids))
            if (r.refused !== undefined) {
                compare([got, UaWallet.lastError], ["", r.refused], r.case)
                refused++
            } else {
                const sig = JSON.parse(got)
                compare([sig.keyData, sig.signature], ["0x", "0x"], r.case)
                verify(sig.members.length > 0, r.case)
                built++
            }
        }
        compare([built, refused], [3, 4])
        compare(UaWallet.uaSig("{}", "[1, \"x\"]"), "")
        compare(UaWallet.lastError, "UAArgument")
    }

    function test_seal_to_a_public_key() {
        const k = kem.keys[0]
        const out = JSON.parse(UaWallet.seal(k.kemPk, "scaas/backup/v1", "0x6161", "0x0102030405"))
        compare(UaWallet.lastError, "")
        compare(out.mlkemCt.length, 2 + 2 * 1568)
        compare(out.x25519Eph.length, 2 + 64)
        compare(fixture.open(k.mnemonic, k.kind, k.version, "scaas/backup/v1", "0x6161", JSON.stringify(out)), "0x0102030405")
        compare(fixture.open(k.mnemonic, k.kind, k.version, "scaas/backup/v1", "0x6162", JSON.stringify(out)), "UASealOpen", "the aad")
        compare(UaWallet.seal("0x01" + "00".repeat(1599), "scaas/backup/v1", "0x", "0x01"), "")
        compare(UaWallet.lastError, "UAKemCheck")
    }

    function test_revoked_after_lock_public_data_readable() {
        const id = fixture.keyOfFreshWallet(0x0101)
        const kd = UaWallet.keyData(id)
        const p = "0x" + "00".repeat(32)
        verify(UaWallet.signUa(id, UaKinds.purposeTag("metatx"), p).length > 2)
        fixture.lockFreshWallet()
        compare(UaWallet.signUa(id, UaKinds.purposeTag("metatx"), p), "")
        compare(UaWallet.lastError, "UAKeyRevoked")
        compare(UaWallet.keyData(id), kd, "public data stays readable")
    }

    function test_a_handle_released_once() {
        const id = fixture.key("twelve_words", 0x0102, 0, 0)
        verify(UaWallet.keyData(id).length > 2)
        compare(fixture.release(id), true)
        compare(fixture.release(id), false, "released once: the second release frees nothing")
        compare(UaWallet.keyData(id), "")
        compare(UaWallet.lastError, "UAArgument", "a released id names nothing")
        compare(fixture.liveHandlesBalanced(), true)
    }
}
