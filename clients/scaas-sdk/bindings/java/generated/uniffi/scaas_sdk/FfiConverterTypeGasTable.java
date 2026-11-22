package uniffi.scaas_sdk;


public enum FfiConverterTypeGasTable implements FfiConverterRustBuffer<GasTable> {
  INSTANCE;

  @Override
  public GasTable read(java.nio.ByteBuffer buf) {
    return new GasTable(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterTypeGasRows.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(GasTable value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.name()) +
            FfiConverterString.INSTANCE.allocationSize(value.family()) +
            FfiConverterTypeGasRows.INSTANCE.allocationSize(value.rows())
      );
  }

  @Override
  public void write(GasTable value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.name(), buf);
      FfiConverterString.INSTANCE.write(value.family(), buf);
      FfiConverterTypeGasRows.INSTANCE.write(value.rows(), buf);
  }
}



