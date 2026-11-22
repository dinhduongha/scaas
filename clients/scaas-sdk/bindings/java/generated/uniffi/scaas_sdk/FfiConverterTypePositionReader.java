package uniffi.scaas_sdk;


public enum FfiConverterTypePositionReader implements FfiConverterRustBuffer<PositionReader> {
  INSTANCE;

  @Override
  public PositionReader read(java.nio.ByteBuffer buf) {
    return new PositionReader(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(PositionReader value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.manager()) +
            FfiConverterString.INSTANCE.allocationSize(value.reader())
      );
  }

  @Override
  public void write(PositionReader value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.manager(), buf);
      FfiConverterString.INSTANCE.write(value.reader(), buf);
  }
}



