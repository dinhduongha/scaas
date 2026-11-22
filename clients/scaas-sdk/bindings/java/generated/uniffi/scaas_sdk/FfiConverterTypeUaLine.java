package uniffi.scaas_sdk;


public enum FfiConverterTypeUaLine implements FfiConverterRustBuffer<UaLine> {
  INSTANCE;

  @Override
  public UaLine read(java.nio.ByteBuffer buf) {
    return new UaLine(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterShort.INSTANCE.read(buf),
      FfiConverterOptionalString.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(UaLine value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.holder()) +
            FfiConverterShort.INSTANCE.allocationSize(value.kind()) +
            FfiConverterOptionalString.INSTANCE.allocationSize(value.pqzHome())
      );
  }

  @Override
  public void write(UaLine value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.holder(), buf);
      FfiConverterShort.INSTANCE.write(value.kind(), buf);
      FfiConverterOptionalString.INSTANCE.write(value.pqzHome(), buf);
  }
}



