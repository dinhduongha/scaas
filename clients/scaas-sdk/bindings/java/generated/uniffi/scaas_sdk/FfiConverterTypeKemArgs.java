package uniffi.scaas_sdk;


public enum FfiConverterTypeKemArgs implements FfiConverterRustBuffer<KemArgs> {
  INSTANCE;

  @Override
  public KemArgs read(java.nio.ByteBuffer buf) {
    return new KemArgs(
      FfiConverterByte.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(KemArgs value) {
      return (
            FfiConverterByte.INSTANCE.allocationSize(value.scheme()) +
            FfiConverterString.INSTANCE.allocationSize(value.mlkemEk()) +
            FfiConverterString.INSTANCE.allocationSize(value.x25519())
      );
  }

  @Override
  public void write(KemArgs value, java.nio.ByteBuffer buf) {
      FfiConverterByte.INSTANCE.write(value.scheme(), buf);
      FfiConverterString.INSTANCE.write(value.mlkemEk(), buf);
      FfiConverterString.INSTANCE.write(value.x25519(), buf);
  }
}



