package uniffi.scaas_sdk;


public enum FfiConverterTypeZetherOwnerRollOver implements FfiConverterRustBuffer<ZetherOwnerRollOver> {
  INSTANCE;

  @Override
  public ZetherOwnerRollOver read(java.nio.ByteBuffer buf) {
    return new ZetherOwnerRollOver(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterInteger.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(ZetherOwnerRollOver value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.seed()) +
            FfiConverterInteger.INSTANCE.allocationSize(value.account()) +
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterString.INSTANCE.allocationSize(value.token()) +
            FfiConverterLong.INSTANCE.allocationSize(value.validUntilBlock())
      );
  }

  @Override
  public void write(ZetherOwnerRollOver value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.seed(), buf);
      FfiConverterInteger.INSTANCE.write(value.account(), buf);
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterString.INSTANCE.write(value.token(), buf);
      FfiConverterLong.INSTANCE.write(value.validUntilBlock(), buf);
  }
}



