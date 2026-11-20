package uniffi.scaas_sdk;

public enum FfiConverterOptionalTypeCursor implements FfiConverterRustBuffer<Cursor> {
  INSTANCE;

  @Override
  public Cursor read(java.nio.ByteBuffer buf) {
    if (buf.get() == (byte)0) {
      return null;
    }
    return FfiConverterTypeCursor.INSTANCE.read(buf);
  }

  @Override
  public long allocationSize(Cursor value) {
    if (value == null) {
      return 1L;
    } else {
      return 1L + FfiConverterTypeCursor.INSTANCE.allocationSize(value);
    }
  }

  @Override
  public void write(Cursor value, java.nio.ByteBuffer buf) {
    if (value == null) {
      buf.put((byte)0);
    } else {
      buf.put((byte)1);
      FfiConverterTypeCursor.INSTANCE.write(value, buf);
    }
  }
}



