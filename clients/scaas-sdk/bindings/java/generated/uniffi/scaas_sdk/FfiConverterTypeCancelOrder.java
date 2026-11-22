package uniffi.scaas_sdk;


public enum FfiConverterTypeCancelOrder implements FfiConverterRustBuffer<CancelOrder> {
  INSTANCE;

  @Override
  public CancelOrder read(java.nio.ByteBuffer buf) {
    return new CancelOrder(
      FfiConverterTypeKeyRef.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterTypeOrderTerms.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(CancelOrder value) {
      return (
            FfiConverterTypeKeyRef.INSTANCE.allocationSize(value.signer()) +
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterString.INSTANCE.allocationSize(value.sellToken()) +
            FfiConverterTypeOrderTerms.INSTANCE.allocationSize(value.order())
      );
  }

  @Override
  public void write(CancelOrder value, java.nio.ByteBuffer buf) {
      FfiConverterTypeKeyRef.INSTANCE.write(value.signer(), buf);
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterString.INSTANCE.write(value.sellToken(), buf);
      FfiConverterTypeOrderTerms.INSTANCE.write(value.order(), buf);
  }
}



