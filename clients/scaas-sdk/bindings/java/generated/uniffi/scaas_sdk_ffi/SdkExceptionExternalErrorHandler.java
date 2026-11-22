package uniffi.scaas_sdk_ffi;


public class SdkExceptionExternalErrorHandler implements UniffiRustCallStatusErrorHandler<uniffi.scaas_sdk.SdkException> {
    @Override
    public uniffi.scaas_sdk.SdkException lift(java.lang.foreign.MemorySegment errorBuf) {
        // In FFM, RustBuffer is already a java.lang.foreign.MemorySegment — pass directly to external package
        return new uniffi.scaas_sdk.SdkExceptionErrorHandler().lift(errorBuf);
    }
}


