package uniffi.scaas_sdk;

public enum FfiConverterOptionalTypeStoredItem implements FfiConverterRustBuffer<StoredItem> {
  INSTANCE;

  @Override
  public StoredItem read(java.nio.ByteBuffer buf) {
    if (buf.get() == (byte)0) {
      return null;
    }
    return FfiConverterTypeStoredItem.INSTANCE.read(buf);
  }

  @Override
  public long allocationSize(StoredItem value) {
    if (value == null) {
      return 1L;
    } else {
      return 1L + FfiConverterTypeStoredItem.INSTANCE.allocationSize(value);
    }
  }

  @Override
  public void write(StoredItem value, java.nio.ByteBuffer buf) {
    if (value == null) {
      buf.put((byte)0);
    } else {
      buf.put((byte)1);
      FfiConverterTypeStoredItem.INSTANCE.write(value, buf);
    }
  }
}



