package uniffi.scaas_sdk;


public final class UniffiVTableCallbackInterfaceForeignAuthenticator {
    public static final java.lang.foreign.StructLayout LAYOUT = java.lang.foreign.MemoryLayout.structLayout(
        java.lang.foreign.ValueLayout.ADDRESS.withName("uniffiFree"),
        java.lang.foreign.ValueLayout.ADDRESS.withName("uniffiClone"),
        java.lang.foreign.ValueLayout.ADDRESS.withName("createPasskey"),
        java.lang.foreign.ValueLayout.ADDRESS.withName("getAssertion"),
        java.lang.foreign.ValueLayout.ADDRESS.withName("platformSecret"),
        java.lang.foreign.ValueLayout.ADDRESS.withName("p256Generate"),
        java.lang.foreign.ValueLayout.ADDRESS.withName("p256Sign")
    );

    private static final long OFFSET_uniffiFree = LAYOUT.byteOffset(java.lang.foreign.MemoryLayout.PathElement.groupElement("uniffiFree"));

    private static final long OFFSET_uniffiClone = LAYOUT.byteOffset(java.lang.foreign.MemoryLayout.PathElement.groupElement("uniffiClone"));

    private static final long OFFSET_createPasskey = LAYOUT.byteOffset(java.lang.foreign.MemoryLayout.PathElement.groupElement("createPasskey"));

    private static final long OFFSET_getAssertion = LAYOUT.byteOffset(java.lang.foreign.MemoryLayout.PathElement.groupElement("getAssertion"));

    private static final long OFFSET_platformSecret = LAYOUT.byteOffset(java.lang.foreign.MemoryLayout.PathElement.groupElement("platformSecret"));

    private static final long OFFSET_p256Generate = LAYOUT.byteOffset(java.lang.foreign.MemoryLayout.PathElement.groupElement("p256Generate"));

    private static final long OFFSET_p256Sign = LAYOUT.byteOffset(java.lang.foreign.MemoryLayout.PathElement.groupElement("p256Sign"));

    private UniffiVTableCallbackInterfaceForeignAuthenticator() {}
    public static java.lang.foreign.MemorySegment getuniffiFree(java.lang.foreign.MemorySegment seg) {
        return (java.lang.foreign.MemorySegment) seg.get(java.lang.foreign.ValueLayout.ADDRESS_UNALIGNED, OFFSET_uniffiFree);
    }

    public static void setuniffiFree(java.lang.foreign.MemorySegment seg, java.lang.foreign.MemorySegment value) {
        seg.set(java.lang.foreign.ValueLayout.ADDRESS_UNALIGNED, OFFSET_uniffiFree, value);
    }
    public static java.lang.foreign.MemorySegment getuniffiClone(java.lang.foreign.MemorySegment seg) {
        return (java.lang.foreign.MemorySegment) seg.get(java.lang.foreign.ValueLayout.ADDRESS_UNALIGNED, OFFSET_uniffiClone);
    }

    public static void setuniffiClone(java.lang.foreign.MemorySegment seg, java.lang.foreign.MemorySegment value) {
        seg.set(java.lang.foreign.ValueLayout.ADDRESS_UNALIGNED, OFFSET_uniffiClone, value);
    }
    public static java.lang.foreign.MemorySegment getcreatePasskey(java.lang.foreign.MemorySegment seg) {
        return (java.lang.foreign.MemorySegment) seg.get(java.lang.foreign.ValueLayout.ADDRESS_UNALIGNED, OFFSET_createPasskey);
    }

    public static void setcreatePasskey(java.lang.foreign.MemorySegment seg, java.lang.foreign.MemorySegment value) {
        seg.set(java.lang.foreign.ValueLayout.ADDRESS_UNALIGNED, OFFSET_createPasskey, value);
    }
    public static java.lang.foreign.MemorySegment getgetAssertion(java.lang.foreign.MemorySegment seg) {
        return (java.lang.foreign.MemorySegment) seg.get(java.lang.foreign.ValueLayout.ADDRESS_UNALIGNED, OFFSET_getAssertion);
    }

    public static void setgetAssertion(java.lang.foreign.MemorySegment seg, java.lang.foreign.MemorySegment value) {
        seg.set(java.lang.foreign.ValueLayout.ADDRESS_UNALIGNED, OFFSET_getAssertion, value);
    }
    public static java.lang.foreign.MemorySegment getplatformSecret(java.lang.foreign.MemorySegment seg) {
        return (java.lang.foreign.MemorySegment) seg.get(java.lang.foreign.ValueLayout.ADDRESS_UNALIGNED, OFFSET_platformSecret);
    }

    public static void setplatformSecret(java.lang.foreign.MemorySegment seg, java.lang.foreign.MemorySegment value) {
        seg.set(java.lang.foreign.ValueLayout.ADDRESS_UNALIGNED, OFFSET_platformSecret, value);
    }
    public static java.lang.foreign.MemorySegment getp256Generate(java.lang.foreign.MemorySegment seg) {
        return (java.lang.foreign.MemorySegment) seg.get(java.lang.foreign.ValueLayout.ADDRESS_UNALIGNED, OFFSET_p256Generate);
    }

    public static void setp256Generate(java.lang.foreign.MemorySegment seg, java.lang.foreign.MemorySegment value) {
        seg.set(java.lang.foreign.ValueLayout.ADDRESS_UNALIGNED, OFFSET_p256Generate, value);
    }
    public static java.lang.foreign.MemorySegment getp256Sign(java.lang.foreign.MemorySegment seg) {
        return (java.lang.foreign.MemorySegment) seg.get(java.lang.foreign.ValueLayout.ADDRESS_UNALIGNED, OFFSET_p256Sign);
    }

    public static void setp256Sign(java.lang.foreign.MemorySegment seg, java.lang.foreign.MemorySegment value) {
        seg.set(java.lang.foreign.ValueLayout.ADDRESS_UNALIGNED, OFFSET_p256Sign, value);
    }

    /**
     * Allocate a new instance in the given arena.
     */
    public static java.lang.foreign.MemorySegment allocate(java.lang.foreign.SegmentAllocator allocator) {
        java.lang.foreign.MemorySegment seg = allocator.allocate(LAYOUT);
        seg.fill((byte) 0);
        return seg;
    }
}
