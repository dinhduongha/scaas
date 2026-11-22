package uniffi.scaas_sdk;


public enum FfiConverterTypeMsigStructureArgs implements FfiConverterRustBuffer<MsigStructureArgs> {
  INSTANCE;

  @Override
  public MsigStructureArgs read(java.nio.ByteBuffer buf) {
    return new MsigStructureArgs(
      FfiConverterShort.INSTANCE.read(buf),
      FfiConverterSequenceTypeMsigMemberArgs.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(MsigStructureArgs value) {
      return (
            FfiConverterShort.INSTANCE.allocationSize(value.threshold()) +
            FfiConverterSequenceTypeMsigMemberArgs.INSTANCE.allocationSize(value.members())
      );
  }

  @Override
  public void write(MsigStructureArgs value, java.nio.ByteBuffer buf) {
      FfiConverterShort.INSTANCE.write(value.threshold(), buf);
      FfiConverterSequenceTypeMsigMemberArgs.INSTANCE.write(value.members(), buf);
  }
}



