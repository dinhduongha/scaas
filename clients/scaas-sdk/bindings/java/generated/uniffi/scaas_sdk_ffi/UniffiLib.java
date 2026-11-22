package uniffi.scaas_sdk_ffi;


// FFM-based library binding. Each FFI function gets a MethodHandle and a wrapper method.
final class UniffiLib {
    private static final java.lang.foreign.Linker LINKER = java.lang.foreign.Linker.nativeLinker();
    private static final java.lang.foreign.SymbolLookup SYMBOLS;

    

    static {
        SYMBOLS = NamespaceLibrary.loadLibrary();
    }

    private static java.lang.invoke.MethodHandle findDowncallHandle(String name, java.lang.foreign.FunctionDescriptor descriptor) {
        return SYMBOLS.find(name)
            .map(s -> LINKER.downcallHandle(s, descriptor))
            .orElseThrow(() -> new RuntimeException("Missing FFI symbol: " + name));
    }

    // uniffi_scaas_sdk_ffi_fn_func_panic_in_call
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_ffi_fn_func_panic_in_call = findDowncallHandle("uniffi_scaas_sdk_ffi_fn_func_panic_in_call", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG));

    static long uniffi_scaas_sdk_ffi_fn_func_panic_in_call(long sdk) {
        try {
            return (long) MH_uniffi_scaas_sdk_ffi_fn_func_panic_in_call.invokeExact(sdk);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rustbuffer_alloc
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rustbuffer_alloc = findDowncallHandle("ffi_scaas_sdk_ffi_rustbuffer_alloc", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment ffi_scaas_sdk_ffi_rustbuffer_alloc(java.lang.foreign.SegmentAllocator _allocator, long size, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_ffi_scaas_sdk_ffi_rustbuffer_alloc.invokeExact(_allocator, size, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rustbuffer_from_bytes
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rustbuffer_from_bytes = findDowncallHandle("ffi_scaas_sdk_ffi_rustbuffer_from_bytes", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, ForeignBytes.LAYOUT, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment ffi_scaas_sdk_ffi_rustbuffer_from_bytes(java.lang.foreign.SegmentAllocator _allocator, java.lang.foreign.MemorySegment bytes, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_ffi_scaas_sdk_ffi_rustbuffer_from_bytes.invokeExact(_allocator, bytes, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rustbuffer_free
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rustbuffer_free = findDowncallHandle("ffi_scaas_sdk_ffi_rustbuffer_free", java.lang.foreign.FunctionDescriptor.ofVoid(RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.ADDRESS));

    static void ffi_scaas_sdk_ffi_rustbuffer_free(java.lang.foreign.MemorySegment buf, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            MH_ffi_scaas_sdk_ffi_rustbuffer_free.invokeExact(buf, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rustbuffer_reserve
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rustbuffer_reserve = findDowncallHandle("ffi_scaas_sdk_ffi_rustbuffer_reserve", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment ffi_scaas_sdk_ffi_rustbuffer_reserve(java.lang.foreign.SegmentAllocator _allocator, java.lang.foreign.MemorySegment buf, long additional, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_ffi_scaas_sdk_ffi_rustbuffer_reserve.invokeExact(_allocator, buf, additional, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_poll_u8
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_poll_u8 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_poll_u8", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS, java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_ffi_rust_future_poll_u8(long handle, java.lang.foreign.MemorySegment callback, long callbackData) {
        try {
            MH_ffi_scaas_sdk_ffi_rust_future_poll_u8.invokeExact(handle, callback, callbackData);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_cancel_u8
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_cancel_u8 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_cancel_u8", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_ffi_rust_future_cancel_u8(long handle) {
        try {
            MH_ffi_scaas_sdk_ffi_rust_future_cancel_u8.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_free_u8
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_free_u8 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_free_u8", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_ffi_rust_future_free_u8(long handle) {
        try {
            MH_ffi_scaas_sdk_ffi_rust_future_free_u8.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_complete_u8
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_complete_u8 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_complete_u8", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_BYTE, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static byte ffi_scaas_sdk_ffi_rust_future_complete_u8(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (byte) MH_ffi_scaas_sdk_ffi_rust_future_complete_u8.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_poll_i8
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_poll_i8 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_poll_i8", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS, java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_ffi_rust_future_poll_i8(long handle, java.lang.foreign.MemorySegment callback, long callbackData) {
        try {
            MH_ffi_scaas_sdk_ffi_rust_future_poll_i8.invokeExact(handle, callback, callbackData);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_cancel_i8
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_cancel_i8 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_cancel_i8", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_ffi_rust_future_cancel_i8(long handle) {
        try {
            MH_ffi_scaas_sdk_ffi_rust_future_cancel_i8.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_free_i8
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_free_i8 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_free_i8", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_ffi_rust_future_free_i8(long handle) {
        try {
            MH_ffi_scaas_sdk_ffi_rust_future_free_i8.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_complete_i8
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_complete_i8 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_complete_i8", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_BYTE, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static byte ffi_scaas_sdk_ffi_rust_future_complete_i8(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (byte) MH_ffi_scaas_sdk_ffi_rust_future_complete_i8.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_poll_u16
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_poll_u16 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_poll_u16", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS, java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_ffi_rust_future_poll_u16(long handle, java.lang.foreign.MemorySegment callback, long callbackData) {
        try {
            MH_ffi_scaas_sdk_ffi_rust_future_poll_u16.invokeExact(handle, callback, callbackData);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_cancel_u16
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_cancel_u16 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_cancel_u16", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_ffi_rust_future_cancel_u16(long handle) {
        try {
            MH_ffi_scaas_sdk_ffi_rust_future_cancel_u16.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_free_u16
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_free_u16 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_free_u16", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_ffi_rust_future_free_u16(long handle) {
        try {
            MH_ffi_scaas_sdk_ffi_rust_future_free_u16.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_complete_u16
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_complete_u16 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_complete_u16", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static short ffi_scaas_sdk_ffi_rust_future_complete_u16(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (short) MH_ffi_scaas_sdk_ffi_rust_future_complete_u16.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_poll_i16
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_poll_i16 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_poll_i16", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS, java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_ffi_rust_future_poll_i16(long handle, java.lang.foreign.MemorySegment callback, long callbackData) {
        try {
            MH_ffi_scaas_sdk_ffi_rust_future_poll_i16.invokeExact(handle, callback, callbackData);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_cancel_i16
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_cancel_i16 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_cancel_i16", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_ffi_rust_future_cancel_i16(long handle) {
        try {
            MH_ffi_scaas_sdk_ffi_rust_future_cancel_i16.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_free_i16
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_free_i16 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_free_i16", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_ffi_rust_future_free_i16(long handle) {
        try {
            MH_ffi_scaas_sdk_ffi_rust_future_free_i16.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_complete_i16
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_complete_i16 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_complete_i16", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static short ffi_scaas_sdk_ffi_rust_future_complete_i16(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (short) MH_ffi_scaas_sdk_ffi_rust_future_complete_i16.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_poll_u32
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_poll_u32 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_poll_u32", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS, java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_ffi_rust_future_poll_u32(long handle, java.lang.foreign.MemorySegment callback, long callbackData) {
        try {
            MH_ffi_scaas_sdk_ffi_rust_future_poll_u32.invokeExact(handle, callback, callbackData);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_cancel_u32
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_cancel_u32 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_cancel_u32", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_ffi_rust_future_cancel_u32(long handle) {
        try {
            MH_ffi_scaas_sdk_ffi_rust_future_cancel_u32.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_free_u32
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_free_u32 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_free_u32", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_ffi_rust_future_free_u32(long handle) {
        try {
            MH_ffi_scaas_sdk_ffi_rust_future_free_u32.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_complete_u32
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_complete_u32 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_complete_u32", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_INT, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static int ffi_scaas_sdk_ffi_rust_future_complete_u32(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (int) MH_ffi_scaas_sdk_ffi_rust_future_complete_u32.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_poll_i32
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_poll_i32 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_poll_i32", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS, java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_ffi_rust_future_poll_i32(long handle, java.lang.foreign.MemorySegment callback, long callbackData) {
        try {
            MH_ffi_scaas_sdk_ffi_rust_future_poll_i32.invokeExact(handle, callback, callbackData);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_cancel_i32
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_cancel_i32 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_cancel_i32", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_ffi_rust_future_cancel_i32(long handle) {
        try {
            MH_ffi_scaas_sdk_ffi_rust_future_cancel_i32.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_free_i32
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_free_i32 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_free_i32", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_ffi_rust_future_free_i32(long handle) {
        try {
            MH_ffi_scaas_sdk_ffi_rust_future_free_i32.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_complete_i32
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_complete_i32 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_complete_i32", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_INT, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static int ffi_scaas_sdk_ffi_rust_future_complete_i32(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (int) MH_ffi_scaas_sdk_ffi_rust_future_complete_i32.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_poll_u64
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_poll_u64 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_poll_u64", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS, java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_ffi_rust_future_poll_u64(long handle, java.lang.foreign.MemorySegment callback, long callbackData) {
        try {
            MH_ffi_scaas_sdk_ffi_rust_future_poll_u64.invokeExact(handle, callback, callbackData);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_cancel_u64
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_cancel_u64 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_cancel_u64", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_ffi_rust_future_cancel_u64(long handle) {
        try {
            MH_ffi_scaas_sdk_ffi_rust_future_cancel_u64.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_free_u64
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_free_u64 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_free_u64", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_ffi_rust_future_free_u64(long handle) {
        try {
            MH_ffi_scaas_sdk_ffi_rust_future_free_u64.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_complete_u64
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_complete_u64 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_complete_u64", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static long ffi_scaas_sdk_ffi_rust_future_complete_u64(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (long) MH_ffi_scaas_sdk_ffi_rust_future_complete_u64.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_poll_i64
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_poll_i64 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_poll_i64", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS, java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_ffi_rust_future_poll_i64(long handle, java.lang.foreign.MemorySegment callback, long callbackData) {
        try {
            MH_ffi_scaas_sdk_ffi_rust_future_poll_i64.invokeExact(handle, callback, callbackData);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_cancel_i64
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_cancel_i64 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_cancel_i64", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_ffi_rust_future_cancel_i64(long handle) {
        try {
            MH_ffi_scaas_sdk_ffi_rust_future_cancel_i64.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_free_i64
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_free_i64 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_free_i64", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_ffi_rust_future_free_i64(long handle) {
        try {
            MH_ffi_scaas_sdk_ffi_rust_future_free_i64.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_complete_i64
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_complete_i64 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_complete_i64", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static long ffi_scaas_sdk_ffi_rust_future_complete_i64(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (long) MH_ffi_scaas_sdk_ffi_rust_future_complete_i64.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_poll_f32
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_poll_f32 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_poll_f32", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS, java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_ffi_rust_future_poll_f32(long handle, java.lang.foreign.MemorySegment callback, long callbackData) {
        try {
            MH_ffi_scaas_sdk_ffi_rust_future_poll_f32.invokeExact(handle, callback, callbackData);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_cancel_f32
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_cancel_f32 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_cancel_f32", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_ffi_rust_future_cancel_f32(long handle) {
        try {
            MH_ffi_scaas_sdk_ffi_rust_future_cancel_f32.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_free_f32
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_free_f32 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_free_f32", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_ffi_rust_future_free_f32(long handle) {
        try {
            MH_ffi_scaas_sdk_ffi_rust_future_free_f32.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_complete_f32
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_complete_f32 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_complete_f32", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_FLOAT, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static float ffi_scaas_sdk_ffi_rust_future_complete_f32(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (float) MH_ffi_scaas_sdk_ffi_rust_future_complete_f32.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_poll_f64
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_poll_f64 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_poll_f64", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS, java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_ffi_rust_future_poll_f64(long handle, java.lang.foreign.MemorySegment callback, long callbackData) {
        try {
            MH_ffi_scaas_sdk_ffi_rust_future_poll_f64.invokeExact(handle, callback, callbackData);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_cancel_f64
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_cancel_f64 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_cancel_f64", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_ffi_rust_future_cancel_f64(long handle) {
        try {
            MH_ffi_scaas_sdk_ffi_rust_future_cancel_f64.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_free_f64
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_free_f64 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_free_f64", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_ffi_rust_future_free_f64(long handle) {
        try {
            MH_ffi_scaas_sdk_ffi_rust_future_free_f64.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_complete_f64
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_complete_f64 = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_complete_f64", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_DOUBLE, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static double ffi_scaas_sdk_ffi_rust_future_complete_f64(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (double) MH_ffi_scaas_sdk_ffi_rust_future_complete_f64.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_poll_rust_buffer
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_poll_rust_buffer = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_poll_rust_buffer", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS, java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_ffi_rust_future_poll_rust_buffer(long handle, java.lang.foreign.MemorySegment callback, long callbackData) {
        try {
            MH_ffi_scaas_sdk_ffi_rust_future_poll_rust_buffer.invokeExact(handle, callback, callbackData);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_cancel_rust_buffer
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_cancel_rust_buffer = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_cancel_rust_buffer", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_ffi_rust_future_cancel_rust_buffer(long handle) {
        try {
            MH_ffi_scaas_sdk_ffi_rust_future_cancel_rust_buffer.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_free_rust_buffer
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_free_rust_buffer = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_free_rust_buffer", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_ffi_rust_future_free_rust_buffer(long handle) {
        try {
            MH_ffi_scaas_sdk_ffi_rust_future_free_rust_buffer.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_complete_rust_buffer
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_complete_rust_buffer = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_complete_rust_buffer", java.lang.foreign.FunctionDescriptor.of(RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static java.lang.foreign.MemorySegment ffi_scaas_sdk_ffi_rust_future_complete_rust_buffer(java.lang.foreign.SegmentAllocator _allocator, long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            return (java.lang.foreign.MemorySegment) MH_ffi_scaas_sdk_ffi_rust_future_complete_rust_buffer.invokeExact(_allocator, handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_poll_void
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_poll_void = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_poll_void", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS, java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_ffi_rust_future_poll_void(long handle, java.lang.foreign.MemorySegment callback, long callbackData) {
        try {
            MH_ffi_scaas_sdk_ffi_rust_future_poll_void.invokeExact(handle, callback, callbackData);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_cancel_void
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_cancel_void = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_cancel_void", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_ffi_rust_future_cancel_void(long handle) {
        try {
            MH_ffi_scaas_sdk_ffi_rust_future_cancel_void.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_free_void
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_free_void = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_free_void", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG));

    static void ffi_scaas_sdk_ffi_rust_future_free_void(long handle) {
        try {
            MH_ffi_scaas_sdk_ffi_rust_future_free_void.invokeExact(handle);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_rust_future_complete_void
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_rust_future_complete_void = findDowncallHandle("ffi_scaas_sdk_ffi_rust_future_complete_void", java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS));

    static void ffi_scaas_sdk_ffi_rust_future_complete_void(long handle, java.lang.foreign.MemorySegment uniffiOutErr) {
        try {
            MH_ffi_scaas_sdk_ffi_rust_future_complete_void.invokeExact(handle, uniffiOutErr);
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // uniffi_scaas_sdk_ffi_checksum_func_panic_in_call
    private static final java.lang.invoke.MethodHandle MH_uniffi_scaas_sdk_ffi_checksum_func_panic_in_call = findDowncallHandle("uniffi_scaas_sdk_ffi_checksum_func_panic_in_call", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_SHORT));

    static short uniffi_scaas_sdk_ffi_checksum_func_panic_in_call() {
        try {
            return (short) MH_uniffi_scaas_sdk_ffi_checksum_func_panic_in_call.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    // ffi_scaas_sdk_ffi_uniffi_contract_version
    private static final java.lang.invoke.MethodHandle MH_ffi_scaas_sdk_ffi_uniffi_contract_version = findDowncallHandle("ffi_scaas_sdk_ffi_uniffi_contract_version", java.lang.foreign.FunctionDescriptor.of(java.lang.foreign.ValueLayout.JAVA_INT));

    static int ffi_scaas_sdk_ffi_uniffi_contract_version() {
        try {
            return (int) MH_ffi_scaas_sdk_ffi_uniffi_contract_version.invokeExact();
        } catch (Throwable _ex) { throw new AssertionError("invokeExact failed", _ex); }
    }

    

    // Integrity checks and initialization must happen after all MethodHandle fields
    // are initialized (static fields are initialized in textual order in Java).
    static {
        NamespaceLibrary.uniffiCheckContractApiVersion();
        NamespaceLibrary.uniffiCheckApiChecksums();
        
        }
}

