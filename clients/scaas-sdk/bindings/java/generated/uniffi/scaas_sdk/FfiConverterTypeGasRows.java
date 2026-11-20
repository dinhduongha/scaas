package uniffi.scaas_sdk;


public enum FfiConverterTypeGasRows implements FfiConverterRustBuffer<GasRows> {
  INSTANCE;

  @Override
  public GasRows read(java.nio.ByteBuffer buf) {
    return new GasRows(
      FfiConverterSequenceTypeGasBase.INSTANCE.read(buf),
      FfiConverterSequenceTypeGasVerify.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(GasRows value) {
      return (
            FfiConverterSequenceTypeGasBase.INSTANCE.allocationSize(value.base()) +
            FfiConverterSequenceTypeGasVerify.INSTANCE.allocationSize(value.verify())
      );
  }

  @Override
  public void write(GasRows value, java.nio.ByteBuffer buf) {
      FfiConverterSequenceTypeGasBase.INSTANCE.write(value.base(), buf);
      FfiConverterSequenceTypeGasVerify.INSTANCE.write(value.verify(), buf);
  }
}



