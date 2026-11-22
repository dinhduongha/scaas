package uniffi.scaas_sdk;


public enum FfiConverterTypeRegister implements FfiConverterRustBuffer<Register> {
  INSTANCE;

  @Override
  public Register read(java.nio.ByteBuffer buf) {
    return new Register(
      FfiConverterTypeKeyRef.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterTypeRegisterAttrs.INSTANCE.read(buf),
      FfiConverterTypeKeyRef.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(Register value) {
      return (
            FfiConverterTypeKeyRef.INSTANCE.allocationSize(value.key()) +
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterTypeRegisterAttrs.INSTANCE.allocationSize(value.attrs()) +
            FfiConverterTypeKeyRef.INSTANCE.allocationSize(value.payer())
      );
  }

  @Override
  public void write(Register value, java.nio.ByteBuffer buf) {
      FfiConverterTypeKeyRef.INSTANCE.write(value.key(), buf);
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterTypeRegisterAttrs.INSTANCE.write(value.attrs(), buf);
      FfiConverterTypeKeyRef.INSTANCE.write(value.payer(), buf);
  }
}



