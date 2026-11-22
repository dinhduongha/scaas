package uniffi.scaas_sdk;


public enum FfiConverterTypeKeyPolicy implements FfiConverterRustBuffer<KeyPolicy> {
  INSTANCE;

  @Override
  public KeyPolicy read(java.nio.ByteBuffer buf) {
    return new KeyPolicy(
      FfiConverterBoolean.INSTANCE.read(buf),
      FfiConverterBoolean.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(KeyPolicy value) {
      return (
            FfiConverterBoolean.INSTANCE.allocationSize(value.biometryCurrentSet()) +
            FfiConverterBoolean.INSTANCE.allocationSize(value.invalidatedByEnrollment())
      );
  }

  @Override
  public void write(KeyPolicy value, java.nio.ByteBuffer buf) {
      FfiConverterBoolean.INSTANCE.write(value.biometryCurrentSet(), buf);
      FfiConverterBoolean.INSTANCE.write(value.invalidatedByEnrollment(), buf);
  }
}



