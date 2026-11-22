package uniffi.scaas_sdk;


public enum FfiConverterTypeRegistrationGas implements FfiConverterRustBuffer<RegistrationGas> {
  INSTANCE;

  @Override
  public RegistrationGas read(java.nio.ByteBuffer buf) {
    return new RegistrationGas(
      FfiConverterInteger.INSTANCE.read(buf),
      FfiConverterSequenceTypeStepGas.INSTANCE.read(buf),
      FfiConverterOptionalLong.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(RegistrationGas value) {
      return (
            FfiConverterInteger.INSTANCE.allocationSize(value.transactions()) +
            FfiConverterSequenceTypeStepGas.INSTANCE.allocationSize(value.steps()) +
            FfiConverterOptionalLong.INSTANCE.allocationSize(value.totalGas())
      );
  }

  @Override
  public void write(RegistrationGas value, java.nio.ByteBuffer buf) {
      FfiConverterInteger.INSTANCE.write(value.transactions(), buf);
      FfiConverterSequenceTypeStepGas.INSTANCE.write(value.steps(), buf);
      FfiConverterOptionalLong.INSTANCE.write(value.totalGas(), buf);
  }
}



