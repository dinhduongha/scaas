package uniffi.scaas_sdk;


public enum FfiConverterTypeMsigMemberArgs implements FfiConverterRustBuffer<MsigMemberArgs> {
  INSTANCE;

  @Override
  public MsigMemberArgs read(java.nio.ByteBuffer buf) {
    return new MsigMemberArgs(
      FfiConverterShort.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterShort.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(MsigMemberArgs value) {
      return (
            FfiConverterShort.INSTANCE.allocationSize(value.kind()) +
            FfiConverterString.INSTANCE.allocationSize(value.id()) +
            FfiConverterShort.INSTANCE.allocationSize(value.weight())
      );
  }

  @Override
  public void write(MsigMemberArgs value, java.nio.ByteBuffer buf) {
      FfiConverterShort.INSTANCE.write(value.kind(), buf);
      FfiConverterString.INSTANCE.write(value.id(), buf);
      FfiConverterShort.INSTANCE.write(value.weight(), buf);
  }
}



