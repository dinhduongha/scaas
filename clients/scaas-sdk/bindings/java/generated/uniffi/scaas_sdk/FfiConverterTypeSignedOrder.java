package uniffi.scaas_sdk;


public enum FfiConverterTypeSignedOrder implements FfiConverterRustBuffer<SignedOrder> {
  INSTANCE;

  @Override
  public SignedOrder read(java.nio.ByteBuffer buf) {
    return new SignedOrder(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(SignedOrder value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.orderHash()) +
            FfiConverterString.INSTANCE.allocationSize(value.order()) +
            FfiConverterString.INSTANCE.allocationSize(value.signature())
      );
  }

  @Override
  public void write(SignedOrder value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.orderHash(), buf);
      FfiConverterString.INSTANCE.write(value.order(), buf);
      FfiConverterString.INSTANCE.write(value.signature(), buf);
  }
}



