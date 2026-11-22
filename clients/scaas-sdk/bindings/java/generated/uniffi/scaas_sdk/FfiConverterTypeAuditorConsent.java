package uniffi.scaas_sdk;


public enum FfiConverterTypeAuditorConsent implements FfiConverterRustBuffer<AuditorConsent> {
  INSTANCE;

  @Override
  public AuditorConsent read(java.nio.ByteBuffer buf) {
    return new AuditorConsent(
      FfiConverterTypeKeyRef.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterInteger.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(AuditorConsent value) {
      return (
            FfiConverterTypeKeyRef.INSTANCE.allocationSize(value.signer()) +
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterString.INSTANCE.allocationSize(value.token()) +
            FfiConverterInteger.INSTANCE.allocationSize(value.epoch())
      );
  }

  @Override
  public void write(AuditorConsent value, java.nio.ByteBuffer buf) {
      FfiConverterTypeKeyRef.INSTANCE.write(value.signer(), buf);
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterString.INSTANCE.write(value.token(), buf);
      FfiConverterInteger.INSTANCE.write(value.epoch(), buf);
  }
}



