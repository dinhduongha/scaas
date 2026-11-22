package uniffi.scaas_sdk;


public enum FfiConverterTypeAddUa implements FfiConverterRustBuffer<AddUa> {
  INSTANCE;

  @Override
  public AddUa read(java.nio.ByteBuffer buf) {
    return new AddUa(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterShort.INSTANCE.read(buf),
      FfiConverterInteger.INSTANCE.read(buf),
      FfiConverterInteger.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(AddUa value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.seed()) +
            FfiConverterShort.INSTANCE.allocationSize(value.kind()) +
            FfiConverterInteger.INSTANCE.allocationSize(value.account()) +
            FfiConverterInteger.INSTANCE.allocationSize(value.index()) +
            FfiConverterString.INSTANCE.allocationSize(value.name())
      );
  }

  @Override
  public void write(AddUa value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.seed(), buf);
      FfiConverterShort.INSTANCE.write(value.kind(), buf);
      FfiConverterInteger.INSTANCE.write(value.account(), buf);
      FfiConverterInteger.INSTANCE.write(value.index(), buf);
      FfiConverterString.INSTANCE.write(value.name(), buf);
  }
}



