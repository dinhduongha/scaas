package uniffi.scaas_sdk;


public enum FfiConverterTypeMemoryProtection implements FfiConverterRustBuffer<MemoryProtection> {
  INSTANCE;

  @Override
  public MemoryProtection read(java.nio.ByteBuffer buf) {
    return new MemoryProtection(
      FfiConverterLong.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(MemoryProtection value) {
      return (
            FfiConverterLong.INSTANCE.allocationSize(value.chunks()) +
            FfiConverterLong.INSTANCE.allocationSize(value.locked()) +
            FfiConverterLong.INSTANCE.allocationSize(value.noDump())
      );
  }

  @Override
  public void write(MemoryProtection value, java.nio.ByteBuffer buf) {
      FfiConverterLong.INSTANCE.write(value.chunks(), buf);
      FfiConverterLong.INSTANCE.write(value.locked(), buf);
      FfiConverterLong.INSTANCE.write(value.noDump(), buf);
  }
}



