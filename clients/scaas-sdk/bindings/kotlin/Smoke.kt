// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// scaas-sdk plan T20e: the Kotlin binding (spec §16.1) over the async API, through official UniFFI's output (generated/), on the
// JVM with JNA. Rows: smartcontracts/vectors/keystore/keystore.json as ../rows.py writes them (args[0]); each container is the
// Kotlin store's `keystore`. Valid rows list their seeds and every seed opens with the rows' passphrase (its accounts listed);
// refused rows fail with their named error. Then: a Kotlin async authenticator's PRF through the copy call (passkey unlock),
// `next` on the subscription, a panic as Internal, a Kotlin exception in the store and in the authenticator (Unexpected on the
// Rust side: the SDK's error, no panic), the load check. Secrets go in only by the copy call. Run by ./run.sh (gate
// `bind-kotlin`).
import com.sun.jna.Library
import com.sun.jna.Native
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.runBlocking
import uniffi.scaas_sdk.*
import uniffi.scaas_sdk_ffi.panicInCall

interface CopyCalls : Library {
    fun scaas_sdk_secret_write(id: Long, src: ByteArray, len: Long): Int
}

val copy: CopyCalls = Native.load("scaas_sdk_ffi", CopyCalls::class.java)
var bad = 0

fun check(c: Boolean, what: () -> String) {
    if (!c) {
        println("FAIL ${what()}")
        bad++
    }
}

fun write(id: ULong, b: ByteArray) = copy.scaas_sdk_secret_write(id.toLong(), b, b.size.toLong())

fun secret(v: String): SecretBytes {
    val b = v.toByteArray()
    val s = secretNew(b.size.toUInt())
    check(write(secretId(s), b) == 0) { "copy call" }
    return s
}

fun unhex(h: String) = String(h.chunked(2).map { it.toInt(16).toByte() }.toByteArray())

class MemStore : ForeignStore {
    val items = ConcurrentHashMap<String, ByteArray>()
    @Volatile var throws = false

    override suspend fun get(name: String, reason: String): StoredItem? {
        if (throws) throw IllegalStateException("the app's store threw")
        return items[name]?.let { StoredItem(it, revOf(it)) }
    }

    @Synchronized
    private fun put(name: String, prevRev: ULong?, bytes: ByteArray) {
        val have = items[name]?.let { revOf(it) }
        if (have != prevRev) throw StoreException.Conflict()
        items[name] = bytes
    }

    override suspend fun putIf(name: String, prevRev: ULong?, bytes: ByteArray, policy: StorePolicy) = put(name, prevRev, bytes)

    override suspend fun delete(name: String) {
        items.remove(name)
    }

    // one caller at a time here: no lock to hold
    override suspend fun lock(name: String): ULong = 1u

    override suspend fun unlock(token: ULong) {}
}

// A PRF: 32 bytes from the salt (deterministic, a test stand-in), written by the copy call into the secret `prfOut` names.
class FakeAuth : ForeignAuthenticator {
    @Volatile var throws = false

    override suspend fun createPasskey(rpId: String, userName: String, exclude: List<ByteArray>): PasskeyCreated =
        throw AuthException.Unavailable()

    override suspend fun getAssertion(req: AssertionRequest, prfOut: ULong): Assertion {
        if (throws) throw IllegalStateException("the app's authenticator threw")
        val salt = req.prfSalt ?: throw AuthException.Refused()
        val out = ByteArray(32) { i -> (salt[i % salt.size].toInt() xor 0x5a xor i).toByte() }
        if (write(prfOut, out) != 0) throw AuthException.Refused()
        return Assertion(byteArrayOf(0xc1.toByte(), 0xed.toByte()), ByteArray(37), ByteArray(0), ByteArray(64), true)
    }

    override suspend fun platformSecret(keyHandle: String, salt: ByteArray, reason: String, policy: KeyPolicy?, out: ULong) =
        throw AuthException.Unavailable()

    override suspend fun p256Generate(policy: KeyPolicy): SePublic = throw AuthException.Unavailable()

    override suspend fun p256Sign(keyHandle: String, uaMsg: ByteArray, reason: String): ByteArray = throw AuthException.Unavailable()
}

fun config() = BindingConfig(listOf(), "wallet.example", limitsDefault(), listOf())

suspend fun start(st: MemStore, auth: FakeAuth = FakeAuth()) = `open`(config(), st, auth)

suspend fun over(text: String) = start(MemStore().also { it.items["keystore"] = text.toByteArray() })

// the error's code (its text: `Display` is the code), or "Ok"
suspend fun failure(f: suspend () -> Unit): String =
    try {
        f()
        "Ok"
    } catch (e: SdkException) {
        e.message ?: ""
    }

const val REPO =
    "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better"
const val PASS = "river-otter-7 ünï"

class Seed(val id: String, val label: String, val words: UInt, val backup: String, val accounts: List<String>)

class Valid(val id: String, val text: String, val seeds: MutableList<Seed> = mutableListOf())

suspend fun rows(path: String) {
    var pass = ""
    val valid = mutableListOf<Valid>()
    val refused = mutableListOf<Triple<String, String, String>>()
    for (line in File(path).readLines()) {
        val f = line.split('\t')
        when (f[0]) {
            "pass" -> pass = unhex(f[1])
            "valid" -> valid += Valid(unhex(f[1]), unhex(f[2]))
            "seed" -> valid.last().seeds += Seed(f[1], unhex(f[2]), f[3].toUInt(), f[4], if (f[5].isEmpty()) listOf() else f[5].split(','))
            "refused" -> refused += Triple(unhex(f[1]), f[2], unhex(f[3]))
        }
    }
    check(valid.size >= 5 && refused.size >= 19) { "control: rows read (${valid.size} valid, ${refused.size} refused)" }
    var opened = 0
    for (r in valid) {
        val sdk = over(r.text)
        val got = sdk.vault().seeds()
        check(got.size == r.seeds.size) { "${r.id}: ${got.size} seeds" }
        for ((g, w) in got.zip(r.seeds)) {
            check(g.id == w.id && g.label == w.label && g.words == w.words && g.backup == w.backup && !g.unlocked) { "${r.id}: seed ${w.id}" }
        }
        for (w in r.seeds) {
            sdk.vault().unlock(w.id, Unlock.Passphrase(secret(pass)))
            check(sdk.vault().seed(w.id).unlocked) { "${r.id} ${w.id} unlocked" }
            check(sdk.account().accounts(w.id).map { it.id } == w.accounts) { "${r.id} ${w.id} accounts" }
            opened++
        }
        r.seeds.firstOrNull()?.let { first ->
            sdk.vault().lock(first.id)
            val e = failure { sdk.vault().unlock(first.id, Unlock.Passphrase(secret("not the one 9"))) }
            check(e == "VaultOpen") { "${r.id}: a wrong passphrase is $e" }
        }
    }
    check(opened >= 5) { "control: seeds were opened ($opened)" }
    println("ok rows: ${valid.size} valid ($opened seeds opened)")
    for ((id, code, text) in refused) {
        val e = failure { over(text).vault().seeds() }
        check(e == code) { "$id: $e, want $code" }
    }
    println("ok rows: ${refused.size} refused by name")
}

fun main(args: Array<String>) = runBlocking {
    check(apiVersion() == 1u) { "load check: apiVersion ${apiVersion()}" }
    rows(args[0])

    val st = MemStore()
    val auth = FakeAuth()
    val sdk = start(st, auth)
    val sub = sdk.subscribe()
    check(sub.next(50u) == null) { "next: nothing yet" }
    val id = sdk.vault().importWords(ImportWords("Main", secret(REPO), secret(PASS))).id
    var changed = false
    while (true) {
        val ev = sub.next(200u) ?: break
        if (ev is Event.KeystoreChanged) changed = true
    }
    check(changed) { "next: KeystoreChanged" }

    // the PRF return: a Kotlin authenticator writes it by the copy call; the passkey unlock opens the seed with it
    sdk.vault().enablePasskeyUnlock(id, secret(PASS))
    sdk.vault().lock(id)
    sdk.vault().unlock(id, Unlock.Passkey)
    check(sdk.vault().seed(id).unlocked) { "passkey unlock by the PRF" }
    println("ok Kotlin store and authenticator: import, PRF by the copy call, passkey unlock, next")

    // a Kotlin exception in the authenticator: Unexpected on the Rust side, the SDK's refusal here, no panic
    sdk.vault().lock(id)
    auth.throws = true
    val ea = failure { sdk.vault().unlock(id, Unlock.Passkey) }
    check(ea != "Ok" && ea != "Internal") { "authenticator exception: $ea" }
    auth.throws = false
    // a Kotlin exception in the store: Unexpected, the store's failure (VaultIo)
    st.throws = true
    val es = failure { sdk.vault().seeds() }
    check(es == "VaultIo") { "store exception: $es" }
    st.throws = false
    check(sdk.vault().seeds().size == 1) { "control: the store again" }
    println("ok Kotlin exceptions: authenticator $ea, store $es")

    // a panic inside a call (the reference library's hook): Internal, the SDK goes on
    val ep = failure { panicInCall(sdk) }
    check(ep == "Internal") { "panic: $ep" }
    check(sdk.vault().seeds().size == 1) { "control: after the panic" }
    println("ok panic $ep")
    println(if (bad == 0) "RESULT kotlin: PASS (0 failures)" else "RESULT kotlin: FAIL ($bad failures)")
    if (bad != 0) kotlin.system.exitProcess(1)
}
