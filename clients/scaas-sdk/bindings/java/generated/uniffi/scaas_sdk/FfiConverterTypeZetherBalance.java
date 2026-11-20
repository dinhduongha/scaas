package uniffi.scaas_sdk;


public enum FfiConverterTypeZetherBalance implements FfiConverterRustBuffer<ZetherBalance> {
  INSTANCE;

  @Override
  public ZetherBalance read(java.nio.ByteBuffer buf) {
    return new ZetherBalance(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(ZetherBalance value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.amount()) +
            FfiConverterLong.INSTANCE.allocationSize(value.block()) +
            FfiConverterLong.INSTANCE.allocationSize(value.accSeq())
      );
  }

  @Override
  public void write(ZetherBalance value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.amount(), buf);
      FfiConverterLong.INSTANCE.write(value.block(), buf);
      FfiConverterLong.INSTANCE.write(value.accSeq(), buf);
  }
}



