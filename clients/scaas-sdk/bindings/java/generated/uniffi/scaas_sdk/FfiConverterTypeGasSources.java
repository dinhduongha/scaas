package uniffi.scaas_sdk;


public enum FfiConverterTypeGasSources implements FfiConverterRustBuffer<GasSources> {
  INSTANCE;

  @Override
  public GasSources read(java.nio.ByteBuffer buf) {
    return new GasSources(
      FfiConverterTypeGasFrom.INSTANCE.read(buf),
      FfiConverterTypeGasFrom.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(GasSources value) {
      return (
            FfiConverterTypeGasFrom.INSTANCE.allocationSize(value.base()) +
            FfiConverterTypeGasFrom.INSTANCE.allocationSize(value.verify())
      );
  }

  @Override
  public void write(GasSources value, java.nio.ByteBuffer buf) {
      FfiConverterTypeGasFrom.INSTANCE.write(value.base(), buf);
      FfiConverterTypeGasFrom.INSTANCE.write(value.verify(), buf);
  }
}



