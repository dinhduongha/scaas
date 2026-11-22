package uniffi.scaas_sdk;


public enum FfiConverterTypeZetherOwnerSetMode implements FfiConverterRustBuffer<ZetherOwnerSetMode> {
  INSTANCE;

  @Override
  public ZetherOwnerSetMode read(java.nio.ByteBuffer buf) {
    return new ZetherOwnerSetMode(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterInteger.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterByte.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(ZetherOwnerSetMode value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.seed()) +
            FfiConverterInteger.INSTANCE.allocationSize(value.account()) +
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterString.INSTANCE.allocationSize(value.token()) +
            FfiConverterByte.INSTANCE.allocationSize(value.mode()) +
            FfiConverterLong.INSTANCE.allocationSize(value.validUntilBlock())
      );
  }

  @Override
  public void write(ZetherOwnerSetMode value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.seed(), buf);
      FfiConverterInteger.INSTANCE.write(value.account(), buf);
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterString.INSTANCE.write(value.token(), buf);
      FfiConverterByte.INSTANCE.write(value.mode(), buf);
      FfiConverterLong.INSTANCE.write(value.validUntilBlock(), buf);
  }
}



