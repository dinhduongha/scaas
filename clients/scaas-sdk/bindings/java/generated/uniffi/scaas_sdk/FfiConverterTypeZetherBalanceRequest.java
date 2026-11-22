package uniffi.scaas_sdk;


public enum FfiConverterTypeZetherBalanceRequest implements FfiConverterRustBuffer<ZetherBalanceRequest> {
  INSTANCE;

  @Override
  public ZetherBalanceRequest read(java.nio.ByteBuffer buf) {
    return new ZetherBalanceRequest(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterInteger.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterBoolean.INSTANCE.read(buf),
      FfiConverterOptionalInteger.INSTANCE.read(buf),
      FfiConverterOptionalInteger.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(ZetherBalanceRequest value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.seed()) +
            FfiConverterInteger.INSTANCE.allocationSize(value.account()) +
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterString.INSTANCE.allocationSize(value.token()) +
            FfiConverterBoolean.INSTANCE.allocationSize(value.pending()) +
            FfiConverterOptionalInteger.INSTANCE.allocationSize(value.tableBits()) +
            FfiConverterOptionalInteger.INSTANCE.allocationSize(value.boundBits())
      );
  }

  @Override
  public void write(ZetherBalanceRequest value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.seed(), buf);
      FfiConverterInteger.INSTANCE.write(value.account(), buf);
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterString.INSTANCE.write(value.token(), buf);
      FfiConverterBoolean.INSTANCE.write(value.pending(), buf);
      FfiConverterOptionalInteger.INSTANCE.write(value.tableBits(), buf);
      FfiConverterOptionalInteger.INSTANCE.write(value.boundBits(), buf);
  }
}



