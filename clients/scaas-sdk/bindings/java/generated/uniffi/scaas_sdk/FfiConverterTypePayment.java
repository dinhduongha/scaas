package uniffi.scaas_sdk;


public enum FfiConverterTypePayment implements FfiConverterRustBuffer<Payment> {
  INSTANCE;

  @Override
  public Payment read(java.nio.ByteBuffer buf) {
    return new Payment(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(Payment value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.from()) +
            FfiConverterString.INSTANCE.allocationSize(value.to()) +
            FfiConverterString.INSTANCE.allocationSize(value.value()) +
            FfiConverterLong.INSTANCE.allocationSize(value.validUntil()) +
            FfiConverterString.INSTANCE.allocationSize(value.relayer())
      );
  }

  @Override
  public void write(Payment value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.from(), buf);
      FfiConverterString.INSTANCE.write(value.to(), buf);
      FfiConverterString.INSTANCE.write(value.value(), buf);
      FfiConverterLong.INSTANCE.write(value.validUntil(), buf);
      FfiConverterString.INSTANCE.write(value.relayer(), buf);
  }
}



