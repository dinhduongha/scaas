// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
// scaas-sdk spec §5, §16.1: the reference library's secret copy calls for Java (plan T20e2; review B12), through the FFM
// API. A secret's bytes cross only here, never through the generated codec: write copies a buffer into the secret named by
// its id and zeroes the buffer, read copies a secret out (the caller zeroes what it read once done), dispose zeroes and frees
// a secret. The native copy is zeroed too. A Java String cannot be zeroed: pass a byte[].
import java.lang.foreign.Arena;
import java.lang.foreign.FunctionDescriptor;
import java.lang.foreign.Linker;
import java.lang.foreign.MemorySegment;
import java.lang.foreign.SymbolLookup;
import java.lang.foreign.ValueLayout;
import java.lang.invoke.MethodHandle;
import java.util.Arrays;

public final class CopyCall {
    private final MethodHandle write;
    private final MethodHandle read;
    private final MethodHandle dispose;

    /** The copy calls of the library at `path`. */
    public CopyCall(String path) {
        SymbolLookup lib = SymbolLookup.libraryLookup(path, Arena.global());
        Linker l = Linker.nativeLinker();
        write = l.downcallHandle(lib.find("scaas_sdk_secret_write").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));
        read = l.downcallHandle(lib.find("scaas_sdk_secret_read").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_LONG, ValueLayout.JAVA_LONG, ValueLayout.ADDRESS, ValueLayout.JAVA_LONG));
        dispose = l.downcallHandle(lib.find("scaas_sdk_secret_dispose").orElseThrow(),
                FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.JAVA_LONG));
    }

    /** `buf` into secret `id` (its length exactly), then `buf` and the native copy zeroed; false on a refusal. */
    public boolean write(long id, byte[] buf) {
        try (Arena a = Arena.ofConfined()) {
            MemorySegment m = a.allocate(Math.max(1, buf.length));
            MemorySegment.copy(buf, 0, m, ValueLayout.JAVA_BYTE, 0, buf.length);
            Arrays.fill(buf, (byte) 0);
            int r = (int) write.invokeExact(id, m, (long) buf.length);
            m.fill((byte) 0);
            return r == 0;
        } catch (Throwable t) {
            Arrays.fill(buf, (byte) 0);
            throw new IllegalStateException(t);
        }
    }

    /** Secret `id` (at most `cap` bytes) out; null when refused. */
    public byte[] read(long id, int cap) {
        try (Arena a = Arena.ofConfined()) {
            MemorySegment m = a.allocate(Math.max(1, cap));
            long n = (long) read.invokeExact(id, m, (long) cap);
            byte[] out = n < 0 ? null : m.asSlice(0, n).toArray(ValueLayout.JAVA_BYTE);
            m.fill((byte) 0);
            return out;
        } catch (Throwable t) {
            throw new IllegalStateException(t);
        }
    }

    /** Secret `id` zeroed and freed; false when unknown. */
    public boolean dispose(long id) {
        try {
            return (int) dispose.invokeExact(id) == 0;
        } catch (Throwable t) {
            throw new IllegalStateException(t);
        }
    }
}
