package uniffi.scaas_sdk;


public enum FfiConverterTypeStoredItem implements FfiConverterRustBuffer<StoredItem> {
  INSTANCE;

  @Override
  public StoredItem read(java.nio.ByteBuffer buf) {
    return new StoredItem(
      FfiConverterByteArray.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(StoredItem value) {
      return (
            FfiConverterByteArray.INSTANCE.allocationSize(value.bytes()) +
            FfiConverterLong.INSTANCE.allocationSize(value.rev())
      );
  }

  @Override
  public void write(StoredItem value, java.nio.ByteBuffer buf) {
      FfiConverterByteArray.INSTANCE.write(value.bytes(), buf);
      FfiConverterLong.INSTANCE.write(value.rev(), buf);
  }
}



