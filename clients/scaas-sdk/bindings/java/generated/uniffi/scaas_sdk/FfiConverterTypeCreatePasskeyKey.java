package uniffi.scaas_sdk;


public enum FfiConverterTypeCreatePasskeyKey implements FfiConverterRustBuffer<CreatePasskeyKey> {
  INSTANCE;

  @Override
  public CreatePasskeyKey read(java.nio.ByteBuffer buf) {
    return new CreatePasskeyKey(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(CreatePasskeyKey value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.seed()) +
            FfiConverterString.INSTANCE.allocationSize(value.name())
      );
  }

  @Override
  public void write(CreatePasskeyKey value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.seed(), buf);
      FfiConverterString.INSTANCE.write(value.name(), buf);
  }
}



