package uniffi.scaas_sdk;


public enum FfiConverterTypeEnvelope implements FfiConverterRustBuffer<Envelope> {
  INSTANCE;

  @Override
  public Envelope read(java.nio.ByteBuffer buf) {
    return new Envelope(
      FfiConverterLong.INSTANCE.read(buf),
      FfiConverterInteger.INSTANCE.read(buf),
      FfiConverterOptionalString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterOptionalString.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(Envelope value) {
      return (
            FfiConverterLong.INSTANCE.allocationSize(value.validUntil()) +
            FfiConverterInteger.INSTANCE.allocationSize(value.mode()) +
            FfiConverterOptionalString.INSTANCE.allocationSize(value.relayer()) +
            FfiConverterString.INSTANCE.allocationSize(value.fee()) +
            FfiConverterOptionalString.INSTANCE.allocationSize(value.feeRecipient())
      );
  }

  @Override
  public void write(Envelope value, java.nio.ByteBuffer buf) {
      FfiConverterLong.INSTANCE.write(value.validUntil(), buf);
      FfiConverterInteger.INSTANCE.write(value.mode(), buf);
      FfiConverterOptionalString.INSTANCE.write(value.relayer(), buf);
      FfiConverterString.INSTANCE.write(value.fee(), buf);
      FfiConverterOptionalString.INSTANCE.write(value.feeRecipient(), buf);
  }
}



