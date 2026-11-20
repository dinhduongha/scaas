package uniffi.scaas_sdk;


public enum FfiConverterTypeBalances implements FfiConverterRustBuffer<Balances> {
  INSTANCE;

  @Override
  public Balances read(java.nio.ByteBuffer buf) {
    return new Balances(
      FfiConverterLong.INSTANCE.read(buf),
      FfiConverterOptionalString.INSTANCE.read(buf),
      FfiConverterSequenceTypeTokenBalance.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(Balances value) {
      return (
            FfiConverterLong.INSTANCE.allocationSize(value.block()) +
            FfiConverterOptionalString.INSTANCE.allocationSize(value._native()) +
            FfiConverterSequenceTypeTokenBalance.INSTANCE.allocationSize(value.tokens())
      );
  }

  @Override
  public void write(Balances value, java.nio.ByteBuffer buf) {
      FfiConverterLong.INSTANCE.write(value.block(), buf);
      FfiConverterOptionalString.INSTANCE.write(value._native(), buf);
      FfiConverterSequenceTypeTokenBalance.INSTANCE.write(value.tokens(), buf);
  }
}



