package uniffi.scaas_sdk;


public enum FfiConverterTypeCancelAll implements FfiConverterRustBuffer<CancelAll> {
  INSTANCE;

  @Override
  public CancelAll read(java.nio.ByteBuffer buf) {
    return new CancelAll(
      FfiConverterTypeKeyRef.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterOptionalString.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(CancelAll value) {
      return (
            FfiConverterTypeKeyRef.INSTANCE.allocationSize(value.signer()) +
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterString.INSTANCE.allocationSize(value.sellToken()) +
            FfiConverterString.INSTANCE.allocationSize(value.dex()) +
            FfiConverterString.INSTANCE.allocationSize(value.batch()) +
            FfiConverterOptionalString.INSTANCE.allocationSize(value.minNonce())
      );
  }

  @Override
  public void write(CancelAll value, java.nio.ByteBuffer buf) {
      FfiConverterTypeKeyRef.INSTANCE.write(value.signer(), buf);
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterString.INSTANCE.write(value.sellToken(), buf);
      FfiConverterString.INSTANCE.write(value.dex(), buf);
      FfiConverterString.INSTANCE.write(value.batch(), buf);
      FfiConverterOptionalString.INSTANCE.write(value.minNonce(), buf);
  }
}



