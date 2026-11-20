package uniffi.scaas_sdk;


public enum FfiConverterTypeKemRecord implements FfiConverterRustBuffer<KemRecord> {
  INSTANCE;

  @Override
  public KemRecord read(java.nio.ByteBuffer buf) {
    return new KemRecord(
      FfiConverterLong.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(KemRecord value) {
      return (
            FfiConverterLong.INSTANCE.allocationSize(value.version()) +
            FfiConverterString.INSTANCE.allocationSize(value.kemPk())
      );
  }

  @Override
  public void write(KemRecord value, java.nio.ByteBuffer buf) {
      FfiConverterLong.INSTANCE.write(value.version(), buf);
      FfiConverterString.INSTANCE.write(value.kemPk(), buf);
  }
}



