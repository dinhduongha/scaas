package uniffi.scaas_sdk;


public enum FfiConverterTypePqzBalance implements FfiConverterRustBuffer<PqzBalance> {
  INSTANCE;

  @Override
  public PqzBalance read(java.nio.ByteBuffer buf) {
    return new PqzBalance(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(PqzBalance value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.amount()) +
            FfiConverterLong.INSTANCE.allocationSize(value.block()) +
            FfiConverterLong.INSTANCE.allocationSize(value.p()) +
            FfiConverterLong.INSTANCE.allocationSize(value.sendCounter())
      );
  }

  @Override
  public void write(PqzBalance value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.amount(), buf);
      FfiConverterLong.INSTANCE.write(value.block(), buf);
      FfiConverterLong.INSTANCE.write(value.p(), buf);
      FfiConverterLong.INSTANCE.write(value.sendCounter(), buf);
  }
}



