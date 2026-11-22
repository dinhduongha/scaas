package uniffi.scaas_sdk;


public enum FfiConverterTypeBindingConfig implements FfiConverterRustBuffer<BindingConfig> {
  INSTANCE;

  @Override
  public BindingConfig read(java.nio.ByteBuffer buf) {
    return new BindingConfig(
      FfiConverterInteger.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf),
      FfiConverterSequenceTypeChainProfile.INSTANCE.read(buf),
      FfiConverterOptionalString.INSTANCE.read(buf),
      FfiConverterTypeLimits.INSTANCE.read(buf),
      FfiConverterSequenceTypeGasTable.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(BindingConfig value) {
      return (
            FfiConverterInteger.INSTANCE.allocationSize(value.expectApi()) +
            FfiConverterLong.INSTANCE.allocationSize(value.needFeatures()) +
            FfiConverterSequenceTypeChainProfile.INSTANCE.allocationSize(value.profiles()) +
            FfiConverterOptionalString.INSTANCE.allocationSize(value.rpId()) +
            FfiConverterTypeLimits.INSTANCE.allocationSize(value.limits()) +
            FfiConverterSequenceTypeGasTable.INSTANCE.allocationSize(value.gasTables())
      );
  }

  @Override
  public void write(BindingConfig value, java.nio.ByteBuffer buf) {
      FfiConverterInteger.INSTANCE.write(value.expectApi(), buf);
      FfiConverterLong.INSTANCE.write(value.needFeatures(), buf);
      FfiConverterSequenceTypeChainProfile.INSTANCE.write(value.profiles(), buf);
      FfiConverterOptionalString.INSTANCE.write(value.rpId(), buf);
      FfiConverterTypeLimits.INSTANCE.write(value.limits(), buf);
      FfiConverterSequenceTypeGasTable.INSTANCE.write(value.gasTables(), buf);
  }
}



