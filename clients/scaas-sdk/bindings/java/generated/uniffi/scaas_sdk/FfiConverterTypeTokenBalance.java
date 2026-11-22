package uniffi.scaas_sdk;


public enum FfiConverterTypeTokenBalance implements FfiConverterRustBuffer<TokenBalance> {
  INSTANCE;

  @Override
  public TokenBalance read(java.nio.ByteBuffer buf) {
    return new TokenBalance(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterByte.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(TokenBalance value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.address()) +
            FfiConverterString.INSTANCE.allocationSize(value.display()) +
            FfiConverterByte.INSTANCE.allocationSize(value.decimals()) +
            FfiConverterString.INSTANCE.allocationSize(value.amount())
      );
  }

  @Override
  public void write(TokenBalance value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.address(), buf);
      FfiConverterString.INSTANCE.write(value.display(), buf);
      FfiConverterByte.INSTANCE.write(value.decimals(), buf);
      FfiConverterString.INSTANCE.write(value.amount(), buf);
  }
}



