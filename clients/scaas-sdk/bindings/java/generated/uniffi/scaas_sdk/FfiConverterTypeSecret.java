package uniffi.scaas_sdk;


public enum FfiConverterTypeSecret implements FfiConverter<Secret, java.lang.foreign.MemorySegment> {
  INSTANCE;
  @Override
  public Secret lift(java.lang.foreign.MemorySegment value) {
      var builtinValue = FfiConverterString.INSTANCE.lift(value);
      return new Secret(builtinValue);
  }
  @Override
  public java.lang.foreign.MemorySegment lower(Secret value) {
      var builtinValue = value.value();
      return FfiConverterString.INSTANCE.lower(builtinValue);
  }
  @Override
  public Secret read(java.nio.ByteBuffer buf) {
      var builtinValue = FfiConverterString.INSTANCE.read(buf);
      return new Secret(builtinValue);
  }
  @Override
  public long allocationSize(Secret value) {
      var builtinValue = value.value();
      return FfiConverterString.INSTANCE.allocationSize(builtinValue);
  }
  @Override
  public void write(Secret value, java.nio.ByteBuffer buf) {
      var builtinValue = value.value();
      FfiConverterString.INSTANCE.write(builtinValue, buf);
  }
}




