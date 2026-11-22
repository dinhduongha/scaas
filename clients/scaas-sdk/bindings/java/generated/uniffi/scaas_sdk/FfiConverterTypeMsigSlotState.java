package uniffi.scaas_sdk;


public enum FfiConverterTypeMsigSlotState implements FfiConverterRustBuffer<MsigSlotState> {
  INSTANCE;

  @Override
  public MsigSlotState read(java.nio.ByteBuffer buf) {
    return new MsigSlotState(
      FfiConverterShort.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterShort.INSTANCE.read(buf),
      FfiConverterBoolean.INSTANCE.read(buf),
      FfiConverterBoolean.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(MsigSlotState value) {
      return (
            FfiConverterShort.INSTANCE.allocationSize(value.kind()) +
            FfiConverterString.INSTANCE.allocationSize(value.id()) +
            FfiConverterShort.INSTANCE.allocationSize(value.weight()) +
            FfiConverterBoolean.INSTANCE.allocationSize(value.enabled()) +
            FfiConverterBoolean.INSTANCE.allocationSize(value.accepted()) +
            FfiConverterString.INSTANCE.allocationSize(value.sigHash())
      );
  }

  @Override
  public void write(MsigSlotState value, java.nio.ByteBuffer buf) {
      FfiConverterShort.INSTANCE.write(value.kind(), buf);
      FfiConverterString.INSTANCE.write(value.id(), buf);
      FfiConverterShort.INSTANCE.write(value.weight(), buf);
      FfiConverterBoolean.INSTANCE.write(value.enabled(), buf);
      FfiConverterBoolean.INSTANCE.write(value.accepted(), buf);
      FfiConverterString.INSTANCE.write(value.sigHash(), buf);
  }
}



