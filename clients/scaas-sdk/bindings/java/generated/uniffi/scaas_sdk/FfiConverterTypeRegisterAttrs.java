package uniffi.scaas_sdk;


public enum FfiConverterTypeRegisterAttrs implements FfiConverterRustBuffer<RegisterAttrs> {
  INSTANCE;

  @Override
  public RegisterAttrs read(java.nio.ByteBuffer buf) {
    return new RegisterAttrs(
      FfiConverterBoolean.INSTANCE.read(buf),
      FfiConverterBoolean.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(RegisterAttrs value) {
      return (
            FfiConverterBoolean.INSTANCE.allocationSize(value.pqzKey()) +
            FfiConverterBoolean.INSTANCE.allocationSize(value.kem())
      );
  }

  @Override
  public void write(RegisterAttrs value, java.nio.ByteBuffer buf) {
      FfiConverterBoolean.INSTANCE.write(value.pqzKey(), buf);
      FfiConverterBoolean.INSTANCE.write(value.kem(), buf);
  }
}



