package uniffi.scaas_sdk;


public enum FfiConverterTypeLiquidityToken implements FfiConverterRustBuffer<LiquidityToken> {
  INSTANCE;

  @Override
  public LiquidityToken read(java.nio.ByteBuffer buf) {
    return new LiquidityToken(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(LiquidityToken value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.token()) +
            FfiConverterString.INSTANCE.allocationSize(value.amount())
      );
  }

  @Override
  public void write(LiquidityToken value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.token(), buf);
      FfiConverterString.INSTANCE.write(value.amount(), buf);
  }
}



