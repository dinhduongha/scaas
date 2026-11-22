// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// scaas-sdk plan T20f: the Swift binding (spec §16.1) over the async API, through official UniFFI's output (generated/), on
// Linux. Rows: smartcontracts/vectors/keystore/keystore.json as ../rows.py writes them (argv[1]; Foundation's JSON parser on
// Linux drops a string's leading U+FEFF, which a refused row holds), each container the Swift store's `keystore`: valid rows
// list their seeds and every seed opens with the rows' passphrase (its accounts listed); refused rows fail with their named
// error. Then: a Swift async authenticator's PRF through the copy call (passkey unlock), `next` on the subscription, a panic as
// Internal, a Swift error in the store and in the authenticator (Unexpected on the Rust side: the SDK's error, no panic), the
// load check. Secrets go in only by the copy call. Built and run by ./run.sh (gate `bind-swift`).
import Foundation

#if canImport(Glibc)
    import Glibc
#endif


var bad = 0
func check(_ c: Bool, _ what: @autoclosure () -> String) {
    if !c {
        print("FAIL: \(what())")
        bad += 1
    }
}


// a secret holding `v`, by the copy call (its buffer zeroed by it; asserted)
func secret(_ v: String) throws -> SecretBytes {
    var b = Array(v.utf8)
    let s = try secretNew(len: UInt32(b.count))
    check(CopyCall.write(secretId(s: s), &b), "copy call")
    check(b.allSatisfy { $0 == 0 }, "the copy call zeroes the caller's buffer")
    return s
}

struct Thrown: Error {}

final class MemStore: ForeignStore, @unchecked Sendable {
    let m = NSLock()
    var items: [String: Data] = [:]
    var throwsNow = false

    func get(name: String, reason: String) async throws -> StoredItem? {
        if m.withLock({ throwsNow }) { throw Thrown() }
        return m.withLock { items[name].map { StoredItem(bytes: $0, rev: revOf(bytes: $0)) } }
    }

    func putIf(name: String, prevRev: UInt64?, bytes: Data, policy: StorePolicy) async throws {
        try m.withLock {
            let have = items[name].map { revOf(bytes: $0) }
            if have != prevRev { throw StoreError.Conflict }
            items[name] = bytes
        }
    }

    func delete(name: String) async throws { m.withLock { _ = items.removeValue(forKey: name) } }

    // one caller at a time here: no lock to hold
    func lock(name: String) async throws -> UInt64 { 1 }

    func unlock(token: UInt64) async {}
}

// A PRF: 32 bytes from the salt (deterministic, a test stand-in), written by the copy call into the secret `prfOut` names.
final class FakeAuth: ForeignAuthenticator, @unchecked Sendable {
    var throwsNow = false

    func createPasskey(rpId: String, userName: String, exclude: [Data]) async throws -> PasskeyCreated {
        throw AuthError.Unavailable
    }

    func getAssertion(req: AssertionRequest, prfOut: UInt64) async throws -> Assertion {
        if throwsNow { throw Thrown() }
        guard let salt = req.prfSalt.map(Array.init) else { throw AuthError.Refused }
        let out = (0..<32).map { i in salt[i % salt.count] ^ 0x5a ^ UInt8(i) }
        var buf = out
        if !CopyCall.write(prfOut, &buf) { throw AuthError.Refused }
        return Assertion(
            credentialId: Data([0xc1, 0xed]), authenticatorData: Data(count: 37), clientDataJson: Data(),
            signature: Data(count: 64), prf: true)
    }

    func platformSecret(keyHandle: String, salt: Data, reason: String, policy: KeyPolicy?, out: UInt64) async throws {
        throw AuthError.Unavailable
    }

    func p256Generate(policy: KeyPolicy) async throws -> SePublic { throw AuthError.Unavailable }

    func p256Sign(keyHandle: String, uaMsg: Data, reason: String) async throws -> Data { throw AuthError.Unavailable }
}

func config(expectApi: UInt32 = 1, needFeatures: UInt64 = features()) -> BindingConfig {
    BindingConfig(
        expectApi: expectApi, needFeatures: needFeatures, profiles: [], rpId: "wallet.example", limits: limitsDefault(),
        gasTables: [])
}

func start(_ st: MemStore, _ auth: FakeAuth = FakeAuth()) async throws -> Sdk {
    try await `open`(config: config(), store: st, authenticator: auth)
}

func over(_ text: String) async throws -> Sdk {
    let st = MemStore()
    st.items["keystore"] = Data(text.utf8)
    return try await start(st)
}

// the error's code (its text: `Display` is the code, each case's `message`), or "Ok"
func failure(_ f: () async throws -> Void) async -> String {
    do {
        try await f()
        return "Ok"
    } catch let e as SdkError {
        // the case's payload is the tuple `(message: String)`
        let payload = Mirror(reflecting: e).children.first?.value
        return payload.flatMap { Mirror(reflecting: $0).children.first?.value as? String } ?? "\(e)"
    } catch {
        return "not an SdkError: \(error)"
    }
}

let REPO =
    "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better"
let PASS = "river-otter-7 ünï"

func unhex(_ h: Substring) -> String {
    var b: [UInt8] = []
    var i = h.startIndex
    while i < h.endIndex {
        let j = h.index(i, offsetBy: 2)
        b.append(UInt8(h[i..<j], radix: 16)!)
        i = j
    }
    return String(decoding: b, as: UTF8.self)
}

struct Seed {
    let id: String, label: String, words: UInt32, backup: String, accounts: [String]
}

func rows(_ path: String) async throws {
    var pass = ""
    var valid: [(id: String, text: String, seeds: [Seed])] = []
    var refused: [(id: String, code: String, text: String)] = []
    for line in try String(contentsOfFile: path, encoding: .utf8).split(separator: "\n") {
        let f = line.split(separator: "\t", omittingEmptySubsequences: false)
        switch f[0] {
        case "pass": pass = unhex(f[1])
        case "valid": valid.append((unhex(f[1]), unhex(f[2]), []))
        case "seed":
            valid[valid.count - 1].seeds.append(
                Seed(
                    id: String(f[1]), label: unhex(f[2]), words: UInt32(f[3])!, backup: String(f[4]),
                    accounts: f[5].isEmpty ? [] : f[5].split(separator: ",").map(String.init)))
        case "refused": refused.append((unhex(f[1]), String(f[2]), unhex(f[3])))
        default: break
        }
    }
    var opened = 0
    for r in valid {
        let sdk = try await over(r.text)
        let got = try await sdk.vault().seeds()
        check(got.count == r.seeds.count, "\(r.id): \(got.count) seeds")
        for (g, w) in zip(got, r.seeds) {
            check(
                g.id == w.id && g.label == w.label && g.words == w.words && g.backup == w.backup && !g.unlocked,
                "\(r.id): seed \(g.id)")
        }
        for w in r.seeds {
            try await sdk.vault().unlock(seed: w.id, unlock: .passphrase(try secret(pass)))
            check(try await sdk.vault().seed(seed: w.id).unlocked, "\(r.id) \(w.id) unlocked")
            let ids = try await sdk.account().accounts(seed: w.id).map { $0.id }
            check(ids == w.accounts, "\(r.id) \(w.id) accounts")
            opened += 1
        }
        if let first = r.seeds.first?.id {
            _ = try await sdk.vault().lock(seed: first)
            let e = await failure { try await sdk.vault().unlock(seed: first, unlock: .passphrase(try secret("not the one 9"))) }
            check(e == "VaultOpen", "\(r.id): a wrong passphrase is \(e)")
        }
    }
    check(valid.count >= 5 && opened >= 5 && refused.count >= 19, "control: \(valid.count) valid, \(opened) opened")
    print("ok rows: \(valid.count) valid (\(opened) seeds opened)")
    for r in refused {
        let e = await failure { _ = try await over(r.text).vault().seeds() }
        check(e == r.code, "\(r.id): \(e), want \(r.code)")
    }
    print("ok rows: \(refused.count) refused by name")
}

func smoke() async throws {
    check(apiVersion() == 1, "load check: apiVersion \(apiVersion())")
    // the opening refuses a library of another api_version or without a needed feature (spec §16.3)
    check(await failure { _ = try await `open`(config: config(expectApi: 2), store: MemStore(), authenticator: nil) } == "AbiMismatch", "load check: api_version 2")
    check(await failure { _ = try await `open`(config: config(needFeatures: 1 << 62), store: MemStore(), authenticator: nil) } == "AbiMismatch", "load check: a feature")
    check(await failure { _ = try await `open`(config: config(), store: MemStore(), authenticator: nil) } == "Ok", "load check: control")

    // the copy calls: a backup's words revealed and read out, then disposed (review B12)
    let fresh = try await start(MemStore()).vault().generate(req: Generate(label: "Fresh", vaultPassphrase: try secret(PASS)))
    let words = try fresh.backup.reveal()
    var text = CopyCall.read(secretId(s: words), cap: Int(secretLen(s: words))) ?? []
    check(String(decoding: text, as: UTF8.self).split(separator: " ").count == 24, "the revealed words, read by the copy call")
    for i in text.indices { text[i] = 0 }
    check(CopyCall.dispose(secretId(s: words)), "dispose")
    check(CopyCall.read(secretId(s: words), cap: 1) == nil, "a disposed secret is refused")
    print("ok copy calls: write zeroes the buffer, a backup revealed and read, disposed")
    try await rows(CommandLine.arguments[1])

    let st = MemStore()
    let auth = FakeAuth()
    let sdk = try await start(st, auth)
    let sub = sdk.subscribe()
    check(try await sub.next(timeoutMs: 50) == nil, "next: nothing yet")
    let id = try await sdk.vault().importWords(req: ImportWords(label: "Main", words: try secret(REPO), vaultPassphrase: try secret(PASS))).id
    var changed = false
    while let ev = try await sub.next(timeoutMs: 200) {
        if case .keystoreChanged = ev { changed = true }
    }
    check(changed, "next: KeystoreChanged")

    // the PRF return: a Swift authenticator writes it by the copy call; the passkey unlock opens the seed with it
    try await sdk.vault().enablePasskeyUnlock(seed: id, vaultPassphrase: try secret(PASS))
    _ = try await sdk.vault().lock(seed: id)
    try await sdk.vault().unlock(seed: id, unlock: .passkey)
    check(try await sdk.vault().seed(seed: id).unlocked, "passkey unlock by the PRF")
    print("ok Swift store and authenticator: import, PRF by the copy call, passkey unlock, next")

    // a Swift error in the authenticator: Unexpected on the Rust side, the SDK's refusal here, no panic
    _ = try await sdk.vault().lock(seed: id)
    auth.throwsNow = true
    let ea = await failure { try await sdk.vault().unlock(seed: id, unlock: .passkey) }
    check(ea == "AuthenticatorRefused", "authenticator error: \(ea)")
    auth.throwsNow = false
    // a Swift error in the store: Unexpected, the store's failure (VaultIo)
    st.m.withLock { st.throwsNow = true }
    let es = await failure { _ = try await sdk.vault().seeds() }
    check(es == "VaultIo", "store error: \(es)")
    st.m.withLock { st.throwsNow = false }
    check(try await sdk.vault().seeds().count == 1, "control: the store again")
    print("ok Swift errors: authenticator \(ea), store \(es)")

    // a panic inside a call (the reference library's hook): Internal, the SDK goes on
    let ep = await failure { try await panicInCall(sdk: sdk) }
    check(ep == "Internal", "panic: \(ep)")
    check(try await sdk.vault().seeds().count == 1, "control: after the panic")
    print("ok panic \(ep)")
}

do {
    try await smoke()
} catch {
    print("FAIL: unexpected error: \(error)")
    bad += 1
}
print(bad == 0 ? "RESULT swift: PASS (0 failures)" : "RESULT swift: FAIL (\(bad) failures)")
exit(bad == 0 ? 0 : 1)
