package uniffi.scaas_sdk;


public enum FfiConverterTypeMsigSlot implements FfiConverter<MsigSlot, java.lang.foreign.MemorySegment> {
  INSTANCE;
  @Override
  public MsigSlot lift(java.lang.foreign.MemorySegment value) {
      var builtinValue = FfiConverterTypeMsigSlotValue.INSTANCE.lift(value);
      return new MsigSlot(builtinValue);
  }
  @Override
  public java.lang.foreign.MemorySegment lower(MsigSlot value) {
      var builtinValue = value.value();
      return FfiConverterTypeMsigSlotValue.INSTANCE.lower(builtinValue);
  }
  @Override
  public MsigSlot read(java.nio.ByteBuffer buf) {
      var builtinValue = FfiConverterTypeMsigSlotValue.INSTANCE.read(buf);
      return new MsigSlot(builtinValue);
  }
  @Override
  public long allocationSize(MsigSlot value) {
      var builtinValue = value.value();
      return FfiConverterTypeMsigSlotValue.INSTANCE.allocationSize(builtinValue);
  }
  @Override
  public void write(MsigSlot value, java.nio.ByteBuffer buf) {
      var builtinValue = value.value();
      FfiConverterTypeMsigSlotValue.INSTANCE.write(builtinValue, buf);
  }
}




