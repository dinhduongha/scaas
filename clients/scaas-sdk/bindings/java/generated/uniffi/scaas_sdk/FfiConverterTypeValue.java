package uniffi.scaas_sdk;


public enum FfiConverterTypeValue implements FfiConverter<Value, java.lang.foreign.MemorySegment> {
  INSTANCE;
  @Override
  public Value lift(java.lang.foreign.MemorySegment value) {
      var builtinValue = FfiConverterString.INSTANCE.lift(value);
      return new Value(builtinValue);
  }
  @Override
  public java.lang.foreign.MemorySegment lower(Value value) {
      var builtinValue = value.value();
      return FfiConverterString.INSTANCE.lower(builtinValue);
  }
  @Override
  public Value read(java.nio.ByteBuffer buf) {
      var builtinValue = FfiConverterString.INSTANCE.read(buf);
      return new Value(builtinValue);
  }
  @Override
  public long allocationSize(Value value) {
      var builtinValue = value.value();
      return FfiConverterString.INSTANCE.allocationSize(builtinValue);
  }
  @Override
  public void write(Value value, java.nio.ByteBuffer buf) {
      var builtinValue = value.value();
      FfiConverterString.INSTANCE.write(builtinValue, buf);
  }
}


