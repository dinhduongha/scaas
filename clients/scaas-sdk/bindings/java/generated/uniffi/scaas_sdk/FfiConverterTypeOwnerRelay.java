package uniffi.scaas_sdk;


public enum FfiConverterTypeOwnerRelay implements FfiConverterRustBuffer<OwnerRelay> {
  INSTANCE;

  @Override
  public OwnerRelay read(java.nio.ByteBuffer buf) {
    return new OwnerRelay(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterTypeEnvelope.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(OwnerRelay value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.batch()) +
            FfiConverterTypeEnvelope.INSTANCE.allocationSize(value.envelope())
      );
  }

  @Override
  public void write(OwnerRelay value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.batch(), buf);
      FfiConverterTypeEnvelope.INSTANCE.write(value.envelope(), buf);
  }
}



