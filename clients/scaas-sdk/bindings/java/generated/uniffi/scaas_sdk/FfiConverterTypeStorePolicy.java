package uniffi.scaas_sdk;


public enum FfiConverterTypeStorePolicy implements FfiConverterRustBuffer<StorePolicy> {
  INSTANCE;

  @Override
  public StorePolicy read(java.nio.ByteBuffer buf) {
    return new StorePolicy(
      FfiConverterBoolean.INSTANCE.read(buf),
      FfiConverterBoolean.INSTANCE.read(buf),
      FfiConverterTypePresence.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(StorePolicy value) {
      return (
            FfiConverterBoolean.INSTANCE.allocationSize(value.deviceOnly()) +
            FfiConverterBoolean.INSTANCE.allocationSize(value.noCloudBackup()) +
            FfiConverterTypePresence.INSTANCE.allocationSize(value.userPresence())
      );
  }

  @Override
  public void write(StorePolicy value, java.nio.ByteBuffer buf) {
      FfiConverterBoolean.INSTANCE.write(value.deviceOnly(), buf);
      FfiConverterBoolean.INSTANCE.write(value.noCloudBackup(), buf);
      FfiConverterTypePresence.INSTANCE.write(value.userPresence(), buf);
  }
}



