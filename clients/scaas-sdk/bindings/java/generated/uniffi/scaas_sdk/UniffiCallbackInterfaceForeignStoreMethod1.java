package uniffi.scaas_sdk;


public final class UniffiCallbackInterfaceForeignStoreMethod1 {
    public static final java.lang.foreign.FunctionDescriptor DESCRIPTOR = java.lang.foreign.FunctionDescriptor.ofVoid(java.lang.foreign.ValueLayout.JAVA_LONG, RustBuffer.LAYOUT, RustBuffer.LAYOUT, RustBuffer.LAYOUT, RustBuffer.LAYOUT, java.lang.foreign.ValueLayout.ADDRESS, java.lang.foreign.ValueLayout.JAVA_LONG, java.lang.foreign.ValueLayout.ADDRESS);

    @FunctionalInterface
    public interface Fn {
        void callback(long uniffiHandle,java.lang.foreign.MemorySegment name,java.lang.foreign.MemorySegment prevRev,java.lang.foreign.MemorySegment bytes,java.lang.foreign.MemorySegment policy,java.lang.foreign.MemorySegment uniffiFutureCallback,long uniffiCallbackData,java.lang.foreign.MemorySegment uniffiOutDroppedCallback);
    }

    public static java.lang.foreign.MemorySegment toUpcallStub(Fn fn, java.lang.foreign.Arena arena) {
        try {
            java.lang.invoke.MethodHandle handle = java.lang.invoke.MethodHandles.lookup()
                .findVirtual(Fn.class, "callback", java.lang.invoke.MethodType.methodType(
                    void.class,
                    long.class,
                    java.lang.foreign.MemorySegment.class,
                    java.lang.foreign.MemorySegment.class,
                    java.lang.foreign.MemorySegment.class,
                    java.lang.foreign.MemorySegment.class,
                    java.lang.foreign.MemorySegment.class,
                    long.class,
                    java.lang.foreign.MemorySegment.class
                ))
                .bindTo(fn);
            return java.lang.foreign.Linker.nativeLinker().upcallStub(handle, DESCRIPTOR, arena);
        } catch (NoSuchMethodException | IllegalAccessException e) {
            throw new AssertionError("Failed to create upcall stub", e);
        }
    }
}
