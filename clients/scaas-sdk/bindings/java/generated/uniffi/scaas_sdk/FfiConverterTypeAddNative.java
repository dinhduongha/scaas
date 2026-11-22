package uniffi.scaas_sdk;


public enum FfiConverterTypeAddNative implements FfiConverterRustBuffer<AddNative> {
  INSTANCE;

  @Override
  public AddNative read(java.nio.ByteBuffer buf) {
    return new AddNative(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterInteger.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(AddNative value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.seed()) +
            FfiConverterString.INSTANCE.allocationSize(value.network()) +
            FfiConverterInteger.INSTANCE.allocationSize(value.index()) +
            FfiConverterString.INSTANCE.allocationSize(value.name())
      );
  }

  @Override
  public void write(AddNative value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.seed(), buf);
      FfiConverterString.INSTANCE.write(value.network(), buf);
      FfiConverterInteger.INSTANCE.write(value.index(), buf);
      FfiConverterString.INSTANCE.write(value.name(), buf);
  }
}



