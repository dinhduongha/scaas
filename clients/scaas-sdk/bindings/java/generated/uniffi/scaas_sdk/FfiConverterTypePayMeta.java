package uniffi.scaas_sdk;


public enum FfiConverterTypePayMeta implements FfiConverterRustBuffer<PayMeta> {
  INSTANCE;

  @Override
  public PayMeta read(java.nio.ByteBuffer buf) {
    return new PayMeta(
      FfiConverterOptionalString.INSTANCE.read(buf),
      FfiConverterOptionalString.INSTANCE.read(buf),
      FfiConverterBoolean.INSTANCE.read(buf),
      FfiConverterTypePayBody.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(PayMeta value) {
      return (
            FfiConverterOptionalString.INSTANCE.allocationSize(value.salt()) +
            FfiConverterOptionalString.INSTANCE.allocationSize(value.payNo()) +
            FfiConverterBoolean.INSTANCE.allocationSize(value.save()) +
            FfiConverterTypePayBody.INSTANCE.allocationSize(value.body())
      );
  }

  @Override
  public void write(PayMeta value, java.nio.ByteBuffer buf) {
      FfiConverterOptionalString.INSTANCE.write(value.salt(), buf);
      FfiConverterOptionalString.INSTANCE.write(value.payNo(), buf);
      FfiConverterBoolean.INSTANCE.write(value.save(), buf);
      FfiConverterTypePayBody.INSTANCE.write(value.body(), buf);
  }
}



