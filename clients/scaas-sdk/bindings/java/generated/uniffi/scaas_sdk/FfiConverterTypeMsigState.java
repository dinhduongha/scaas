package uniffi.scaas_sdk;


public enum FfiConverterTypeMsigState implements FfiConverterRustBuffer<MsigState> {
  INSTANCE;

  @Override
  public MsigState read(java.nio.ByteBuffer buf) {
    return new MsigState(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterTypeMsigStructureArgs.INSTANCE.read(buf),
      FfiConverterShort.INSTANCE.read(buf),
      FfiConverterSequenceTypeMsigSlotState.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf),
      FfiConverterInteger.INSTANCE.read(buf),
      FfiConverterBoolean.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(MsigState value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.ua()) +
            FfiConverterTypeMsigStructureArgs.INSTANCE.allocationSize(value.first()) +
            FfiConverterShort.INSTANCE.allocationSize(value.threshold()) +
            FfiConverterSequenceTypeMsigSlotState.INSTANCE.allocationSize(value.slots()) +
            FfiConverterLong.INSTANCE.allocationSize(value.version()) +
            FfiConverterInteger.INSTANCE.allocationSize(value.activeWeight()) +
            FfiConverterBoolean.INSTANCE.allocationSize(value.active())
      );
  }

  @Override
  public void write(MsigState value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.ua(), buf);
      FfiConverterTypeMsigStructureArgs.INSTANCE.write(value.first(), buf);
      FfiConverterShort.INSTANCE.write(value.threshold(), buf);
      FfiConverterSequenceTypeMsigSlotState.INSTANCE.write(value.slots(), buf);
      FfiConverterLong.INSTANCE.write(value.version(), buf);
      FfiConverterInteger.INSTANCE.write(value.activeWeight(), buf);
      FfiConverterBoolean.INSTANCE.write(value.active(), buf);
  }
}



