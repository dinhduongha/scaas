package uniffi.scaas_sdk;


public enum FfiConverterTypePqzLeg implements FfiConverterRustBuffer<PqzLeg> {
  INSTANCE;

  @Override
  public PqzLeg read(java.nio.ByteBuffer buf) {
    return new PqzLeg(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(PqzLeg value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.toUa()) +
            FfiConverterString.INSTANCE.allocationSize(value.amount())
      );
  }

  @Override
  public void write(PqzLeg value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.toUa(), buf);
      FfiConverterString.INSTANCE.write(value.amount(), buf);
  }
}



