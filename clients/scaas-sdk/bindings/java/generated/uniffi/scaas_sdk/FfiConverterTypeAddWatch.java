package uniffi.scaas_sdk;


public enum FfiConverterTypeAddWatch implements FfiConverterRustBuffer<AddWatch> {
  INSTANCE;

  @Override
  public AddWatch read(java.nio.ByteBuffer buf) {
    return new AddWatch(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(AddWatch value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.seed()) +
            FfiConverterString.INSTANCE.allocationSize(value.watch()) +
            FfiConverterString.INSTANCE.allocationSize(value.name())
      );
  }

  @Override
  public void write(AddWatch value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.seed(), buf);
      FfiConverterString.INSTANCE.write(value.watch(), buf);
      FfiConverterString.INSTANCE.write(value.name(), buf);
  }
}



