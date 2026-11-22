package uniffi.scaas_sdk;


public enum FfiConverterTypeGasLine implements FfiConverterRustBuffer<GasLine> {
  INSTANCE;

  @Override
  public GasLine read(java.nio.ByteBuffer buf) {
    return new GasLine(
      FfiConverterOptionalString.INSTANCE.read(buf),
      FfiConverterOptionalString.INSTANCE.read(buf),
      FfiConverterByte.INSTANCE.read(buf),
      FfiConverterBoolean.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(GasLine value) {
      return (
            FfiConverterOptionalString.INSTANCE.allocationSize(value.registry()) +
            FfiConverterOptionalString.INSTANCE.allocationSize(value.path()) +
            FfiConverterByte.INSTANCE.allocationSize(value.depth()) +
            FfiConverterBoolean.INSTANCE.allocationSize(value.write())
      );
  }

  @Override
  public void write(GasLine value, java.nio.ByteBuffer buf) {
      FfiConverterOptionalString.INSTANCE.write(value.registry(), buf);
      FfiConverterOptionalString.INSTANCE.write(value.path(), buf);
      FfiConverterByte.INSTANCE.write(value.depth(), buf);
      FfiConverterBoolean.INSTANCE.write(value.write(), buf);
  }
}



