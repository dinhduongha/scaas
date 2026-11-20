package uniffi.scaas_sdk;


public enum FfiConverterTypeCreateSeKey implements FfiConverterRustBuffer<CreateSeKey> {
  INSTANCE;

  @Override
  public CreateSeKey read(java.nio.ByteBuffer buf) {
    return new CreateSeKey(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterTypeKeyPolicy.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(CreateSeKey value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.seed()) +
            FfiConverterString.INSTANCE.allocationSize(value.name()) +
            FfiConverterTypeKeyPolicy.INSTANCE.allocationSize(value.policy())
      );
  }

  @Override
  public void write(CreateSeKey value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.seed(), buf);
      FfiConverterString.INSTANCE.write(value.name(), buf);
      FfiConverterTypeKeyPolicy.INSTANCE.write(value.policy(), buf);
  }
}



