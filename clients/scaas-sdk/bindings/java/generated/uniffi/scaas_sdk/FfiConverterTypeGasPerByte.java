package uniffi.scaas_sdk;


public enum FfiConverterTypeGasPerByte implements FfiConverterRustBuffer<GasPerByte> {
  INSTANCE;

  @Override
  public GasPerByte read(java.nio.ByteBuffer buf) {
    return new GasPerByte(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(GasPerByte value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.input()) +
            FfiConverterLong.INSTANCE.allocationSize(value.gas())
      );
  }

  @Override
  public void write(GasPerByte value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.input(), buf);
      FfiConverterLong.INSTANCE.write(value.gas(), buf);
  }
}



