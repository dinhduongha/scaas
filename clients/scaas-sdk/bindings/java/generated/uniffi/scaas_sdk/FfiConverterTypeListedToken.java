package uniffi.scaas_sdk;


public enum FfiConverterTypeListedToken implements FfiConverterRustBuffer<ListedToken> {
  INSTANCE;

  @Override
  public ListedToken read(java.nio.ByteBuffer buf) {
    return new ListedToken(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterByte.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(ListedToken value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.address()) +
            FfiConverterString.INSTANCE.allocationSize(value.symbol()) +
            FfiConverterByte.INSTANCE.allocationSize(value.decimals())
      );
  }

  @Override
  public void write(ListedToken value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.address(), buf);
      FfiConverterString.INSTANCE.write(value.symbol(), buf);
      FfiConverterByte.INSTANCE.write(value.decimals(), buf);
  }
}



