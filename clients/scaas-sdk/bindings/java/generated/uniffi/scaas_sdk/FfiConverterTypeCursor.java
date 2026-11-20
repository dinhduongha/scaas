package uniffi.scaas_sdk;


public enum FfiConverterTypeCursor implements FfiConverterRustBuffer<Cursor> {
  INSTANCE;

  @Override
  public Cursor read(java.nio.ByteBuffer buf) {
    return new Cursor(
      FfiConverterLong.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(Cursor value) {
      return (
            FfiConverterLong.INSTANCE.allocationSize(value.block()) +
            FfiConverterLong.INSTANCE.allocationSize(value.logIndex())
      );
  }

  @Override
  public void write(Cursor value, java.nio.ByteBuffer buf) {
      FfiConverterLong.INSTANCE.write(value.block(), buf);
      FfiConverterLong.INSTANCE.write(value.logIndex(), buf);
  }
}



