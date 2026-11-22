package uniffi.scaas_sdk_ffi;


public interface UniffiRustCallStatusErrorHandler<E extends java.lang.Exception> {
    E lift(java.lang.foreign.MemorySegment errorBuf);
}

