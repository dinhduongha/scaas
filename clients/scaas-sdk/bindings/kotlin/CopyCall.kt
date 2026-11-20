// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// scaas-sdk spec §5, §16.1: the reference library's secret copy calls for Kotlin (plan T20e; review B12), through JNA. A
// secret's bytes cross only here, never through the generated codec: write copies a buffer into the secret named by its id
// and zeroes the buffer, read copies a secret out (the caller zeroes what it read once done), dispose zeroes and frees it.
import com.sun.jna.Library
import com.sun.jna.Native

object CopyCall {
    private interface Lib : Library {
        fun scaas_sdk_secret_write(id: Long, src: ByteArray, len: Long): Int

        fun scaas_sdk_secret_read(id: Long, dst: ByteArray, cap: Long): Long

        fun scaas_sdk_secret_dispose(id: Long): Int
    }

    private val lib: Lib = Native.load("scaas_sdk_ffi", Lib::class.java)

    /** `buf` into secret `id` (its length exactly), then `buf` zeroed (also on a refusal); false on a refusal. */
    fun write(id: ULong, buf: ByteArray): Boolean {
        val r = lib.scaas_sdk_secret_write(id.toLong(), buf, buf.size.toLong())
        buf.fill(0)
        return r == 0
    }

    /** Secret `id` (at most `cap` bytes) out; null when refused. */
    fun read(id: ULong, cap: Int): ByteArray? {
        val out = ByteArray(cap)
        val n = lib.scaas_sdk_secret_read(id.toLong(), out, cap.toLong())
        return if (n < 0) null else out.copyOf(n.toInt()).also { out.fill(0) }
    }

    /** Secret `id` zeroed and freed; false when unknown. */
    fun dispose(id: ULong): Boolean = lib.scaas_sdk_secret_dispose(id.toLong()) == 0
}
