package uniffi.scaas_sdk;


public enum FfiConverterTypeWrapOrderTerms implements FfiConverterRustBuffer<WrapOrderTerms> {
  INSTANCE;

  @Override
  public WrapOrderTerms read(java.nio.ByteBuffer buf) {
    return new WrapOrderTerms(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterByte.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(WrapOrderTerms value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.from()) +
            FfiConverterString.INSTANCE.allocationSize(value.wrappedToken()) +
            FfiConverterString.INSTANCE.allocationSize(value.amount()) +
            FfiConverterString.INSTANCE.allocationSize(value.minMinted()) +
            FfiConverterString.INSTANCE.allocationSize(value.minFill()) +
            FfiConverterString.INSTANCE.allocationSize(value.fee()) +
            FfiConverterString.INSTANCE.allocationSize(value.relayer()) +
            FfiConverterString.INSTANCE.allocationSize(value.destination()) +
            FfiConverterByte.INSTANCE.allocationSize(value.flags()) +
            FfiConverterString.INSTANCE.allocationSize(value.batch()) +
            FfiConverterString.INSTANCE.allocationSize(value.nonce()) +
            FfiConverterString.INSTANCE.allocationSize(value.validUntil())
      );
  }

  @Override
  public void write(WrapOrderTerms value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.from(), buf);
      FfiConverterString.INSTANCE.write(value.wrappedToken(), buf);
      FfiConverterString.INSTANCE.write(value.amount(), buf);
      FfiConverterString.INSTANCE.write(value.minMinted(), buf);
      FfiConverterString.INSTANCE.write(value.minFill(), buf);
      FfiConverterString.INSTANCE.write(value.fee(), buf);
      FfiConverterString.INSTANCE.write(value.relayer(), buf);
      FfiConverterString.INSTANCE.write(value.destination(), buf);
      FfiConverterByte.INSTANCE.write(value.flags(), buf);
      FfiConverterString.INSTANCE.write(value.batch(), buf);
      FfiConverterString.INSTANCE.write(value.nonce(), buf);
      FfiConverterString.INSTANCE.write(value.validUntil(), buf);
  }
}



