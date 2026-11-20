package uniffi.scaas_sdk;


public class StoreExceptionErrorHandler implements UniffiRustCallStatusErrorHandler<StoreException> {
  @Override
  public StoreException lift(java.lang.foreign.MemorySegment errorBuf){
     return FfiConverterTypeStoreError.INSTANCE.lift(errorBuf);
  }
}

