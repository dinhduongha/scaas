package uniffi.scaas_sdk;


public enum FfiConverterTypeTokenInfo implements FfiConverterRustBuffer<TokenInfo> {
  INSTANCE;

  @Override
  public TokenInfo read(java.nio.ByteBuffer buf) {
    return new TokenInfo(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterByte.INSTANCE.read(buf),
      FfiConverterBoolean.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(TokenInfo value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.address()) +
            FfiConverterString.INSTANCE.allocationSize(value.name()) +
            FfiConverterString.INSTANCE.allocationSize(value.symbol()) +
            FfiConverterByte.INSTANCE.allocationSize(value.decimals()) +
            FfiConverterBoolean.INSTANCE.allocationSize(value.listed()) +
            FfiConverterString.INSTANCE.allocationSize(value.display())
      );
  }

  @Override
  public void write(TokenInfo value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.address(), buf);
      FfiConverterString.INSTANCE.write(value.name(), buf);
      FfiConverterString.INSTANCE.write(value.symbol(), buf);
      FfiConverterByte.INSTANCE.write(value.decimals(), buf);
      FfiConverterBoolean.INSTANCE.write(value.listed(), buf);
      FfiConverterString.INSTANCE.write(value.display(), buf);
  }
}



