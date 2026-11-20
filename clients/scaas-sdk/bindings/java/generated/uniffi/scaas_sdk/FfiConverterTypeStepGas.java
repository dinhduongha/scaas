package uniffi.scaas_sdk;


public enum FfiConverterTypeStepGas implements FfiConverterRustBuffer<StepGas> {
  INSTANCE;

  @Override
  public StepGas read(java.nio.ByteBuffer buf) {
    return new StepGas(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterOptionalLong.INSTANCE.read(buf),
      FfiConverterOptionalLong.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(StepGas value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.entry()) +
            FfiConverterOptionalLong.INSTANCE.allocationSize(value.gas()) +
            FfiConverterOptionalLong.INSTANCE.allocationSize(value.regularGas())
      );
  }

  @Override
  public void write(StepGas value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.entry(), buf);
      FfiConverterOptionalLong.INSTANCE.write(value.gas(), buf);
      FfiConverterOptionalLong.INSTANCE.write(value.regularGas(), buf);
  }
}



