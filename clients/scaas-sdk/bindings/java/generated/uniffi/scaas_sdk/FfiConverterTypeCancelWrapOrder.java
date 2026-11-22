package uniffi.scaas_sdk;


public enum FfiConverterTypeCancelWrapOrder implements FfiConverterRustBuffer<CancelWrapOrder> {
  INSTANCE;

  @Override
  public CancelWrapOrder read(java.nio.ByteBuffer buf) {
    return new CancelWrapOrder(
      FfiConverterTypeKeyRef.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterTypeWrapOrderTerms.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(CancelWrapOrder value) {
      return (
            FfiConverterTypeKeyRef.INSTANCE.allocationSize(value.signer()) +
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterString.INSTANCE.allocationSize(value.token()) +
            FfiConverterTypeWrapOrderTerms.INSTANCE.allocationSize(value.order())
      );
  }

  @Override
  public void write(CancelWrapOrder value, java.nio.ByteBuffer buf) {
      FfiConverterTypeKeyRef.INSTANCE.write(value.signer(), buf);
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterString.INSTANCE.write(value.token(), buf);
      FfiConverterTypeWrapOrderTerms.INSTANCE.write(value.order(), buf);
  }
}



