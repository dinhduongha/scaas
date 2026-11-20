package uniffi.scaas_sdk;


public enum FfiConverterTypePayerAuth implements FfiConverterRustBuffer<PayerAuth> {
  INSTANCE;

  @Override
  public PayerAuth read(java.nio.ByteBuffer buf) {
    return new PayerAuth(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(PayerAuth value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.keyData()) +
            FfiConverterString.INSTANCE.allocationSize(value.signature())
      );
  }

  @Override
  public void write(PayerAuth value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.keyData(), buf);
      FfiConverterString.INSTANCE.write(value.signature(), buf);
  }
}



