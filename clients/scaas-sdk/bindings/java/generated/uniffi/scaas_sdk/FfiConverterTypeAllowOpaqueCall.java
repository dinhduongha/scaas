package uniffi.scaas_sdk;


public enum FfiConverterTypeAllowOpaqueCall implements FfiConverter<AllowOpaqueCall, java.lang.Byte> {
  INSTANCE;
  @Override
  public AllowOpaqueCall lift(java.lang.Byte value) {
      var builtinValue = FfiConverterBoolean.INSTANCE.lift(value);
      return new AllowOpaqueCall(builtinValue);
  }
  @Override
  public java.lang.Byte lower(AllowOpaqueCall value) {
      var builtinValue = value.value();
      return FfiConverterBoolean.INSTANCE.lower(builtinValue);
  }
  @Override
  public AllowOpaqueCall read(java.nio.ByteBuffer buf) {
      var builtinValue = FfiConverterBoolean.INSTANCE.read(buf);
      return new AllowOpaqueCall(builtinValue);
  }
  @Override
  public long allocationSize(AllowOpaqueCall value) {
      var builtinValue = value.value();
      return FfiConverterBoolean.INSTANCE.allocationSize(builtinValue);
  }
  @Override
  public void write(AllowOpaqueCall value, java.nio.ByteBuffer buf) {
      var builtinValue = value.value();
      FfiConverterBoolean.INSTANCE.write(builtinValue, buf);
  }
}




