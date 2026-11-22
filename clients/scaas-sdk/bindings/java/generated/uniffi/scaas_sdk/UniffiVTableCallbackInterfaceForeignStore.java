package uniffi.scaas_sdk;


public final class UniffiVTableCallbackInterfaceForeignStore {
    public static final java.lang.foreign.StructLayout LAYOUT = java.lang.foreign.MemoryLayout.structLayout(
        java.lang.foreign.ValueLayout.ADDRESS.withName("uniffiFree"),
        java.lang.foreign.ValueLayout.ADDRESS.withName("uniffiClone"),
        java.lang.foreign.ValueLayout.ADDRESS.withName("get"),
        java.lang.foreign.ValueLayout.ADDRESS.withName("putIf"),
        java.lang.foreign.ValueLayout.ADDRESS.withName("delete"),
        java.lang.foreign.ValueLayout.ADDRESS.withName("lock"),
        java.lang.foreign.ValueLayout.ADDRESS.withName("unlock")
    );

    private static final long OFFSET_uniffiFree = LAYOUT.byteOffset(java.lang.foreign.MemoryLayout.PathElement.groupElement("uniffiFree"));

    private static final long OFFSET_uniffiClone = LAYOUT.byteOffset(java.lang.foreign.MemoryLayout.PathElement.groupElement("uniffiClone"));

    private static final long OFFSET_get = LAYOUT.byteOffset(java.lang.foreign.MemoryLayout.PathElement.groupElement("get"));

    private static final long OFFSET_putIf = LAYOUT.byteOffset(java.lang.foreign.MemoryLayout.PathElement.groupElement("putIf"));

    private static final long OFFSET_delete = LAYOUT.byteOffset(java.lang.foreign.MemoryLayout.PathElement.groupElement("delete"));

    private static final long OFFSET_lock = LAYOUT.byteOffset(java.lang.foreign.MemoryLayout.PathElement.groupElement("lock"));

    private static final long OFFSET_unlock = LAYOUT.byteOffset(java.lang.foreign.MemoryLayout.PathElement.groupElement("unlock"));

    private UniffiVTableCallbackInterfaceForeignStore() {}
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
    public static java.lang.foreign.MemorySegment getget(java.lang.foreign.MemorySegment seg) {
        return (java.lang.foreign.MemorySegment) seg.get(java.lang.foreign.ValueLayout.ADDRESS_UNALIGNED, OFFSET_get);
    }

    public static void setget(java.lang.foreign.MemorySegment seg, java.lang.foreign.MemorySegment value) {
        seg.set(java.lang.foreign.ValueLayout.ADDRESS_UNALIGNED, OFFSET_get, value);
    }
    public static java.lang.foreign.MemorySegment getputIf(java.lang.foreign.MemorySegment seg) {
        return (java.lang.foreign.MemorySegment) seg.get(java.lang.foreign.ValueLayout.ADDRESS_UNALIGNED, OFFSET_putIf);
    }

    public static void setputIf(java.lang.foreign.MemorySegment seg, java.lang.foreign.MemorySegment value) {
        seg.set(java.lang.foreign.ValueLayout.ADDRESS_UNALIGNED, OFFSET_putIf, value);
    }
    public static java.lang.foreign.MemorySegment getdelete(java.lang.foreign.MemorySegment seg) {
        return (java.lang.foreign.MemorySegment) seg.get(java.lang.foreign.ValueLayout.ADDRESS_UNALIGNED, OFFSET_delete);
    }

    public static void setdelete(java.lang.foreign.MemorySegment seg, java.lang.foreign.MemorySegment value) {
        seg.set(java.lang.foreign.ValueLayout.ADDRESS_UNALIGNED, OFFSET_delete, value);
    }
    public static java.lang.foreign.MemorySegment getlock(java.lang.foreign.MemorySegment seg) {
        return (java.lang.foreign.MemorySegment) seg.get(java.lang.foreign.ValueLayout.ADDRESS_UNALIGNED, OFFSET_lock);
    }

    public static void setlock(java.lang.foreign.MemorySegment seg, java.lang.foreign.MemorySegment value) {
        seg.set(java.lang.foreign.ValueLayout.ADDRESS_UNALIGNED, OFFSET_lock, value);
    }
    public static java.lang.foreign.MemorySegment getunlock(java.lang.foreign.MemorySegment seg) {
        return (java.lang.foreign.MemorySegment) seg.get(java.lang.foreign.ValueLayout.ADDRESS_UNALIGNED, OFFSET_unlock);
    }

    public static void setunlock(java.lang.foreign.MemorySegment seg, java.lang.foreign.MemorySegment value) {
        seg.set(java.lang.foreign.ValueLayout.ADDRESS_UNALIGNED, OFFSET_unlock, value);
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

