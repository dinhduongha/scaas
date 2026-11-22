package uniffi.scaas_sdk;


public enum FfiConverterTypeMsigUpdatePlan implements FfiConverterRustBuffer<MsigUpdatePlan> {
  INSTANCE;

  @Override
  public MsigUpdatePlan read(java.nio.ByteBuffer buf) {
    return new MsigUpdatePlan(
      FfiConverterTypeRegistryWrite.INSTANCE.read(buf),
      FfiConverterSequenceString.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(MsigUpdatePlan value) {
      return (
            FfiConverterTypeRegistryWrite.INSTANCE.allocationSize(value.write()) +
            FfiConverterSequenceString.INSTANCE.allocationSize(value.warnings())
      );
  }

  @Override
  public void write(MsigUpdatePlan value, java.nio.ByteBuffer buf) {
      FfiConverterTypeRegistryWrite.INSTANCE.write(value.write(), buf);
      FfiConverterSequenceString.INSTANCE.write(value.warnings(), buf);
  }
}



