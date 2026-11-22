package uniffi.scaas_sdk;


public class SdkExceptionErrorHandler implements UniffiRustCallStatusErrorHandler<SdkException> {
  @Override
  public SdkException lift(java.lang.foreign.MemorySegment errorBuf){
     return FfiConverterTypeSdkError.INSTANCE.lift(errorBuf);
  }
}

