package uniffi.scaas_sdk;


public class AuthExceptionErrorHandler implements UniffiRustCallStatusErrorHandler<AuthException> {
  @Override
  public AuthException lift(java.lang.foreign.MemorySegment errorBuf){
     return FfiConverterTypeAuthError.INSTANCE.lift(errorBuf);
  }
}

