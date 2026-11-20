package uniffi.scaas_sdk;


public enum FfiConverterTypeWrapOrder implements FfiConverterRustBuffer<WrapOrder> {
  INSTANCE;

  @Override
  public WrapOrder read(java.nio.ByteBuffer buf) {
    return new WrapOrder(
      FfiConverterTypeKeyRef.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterOptionalString.INSTANCE.read(buf),
      FfiConverterByte.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterOptionalString.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(WrapOrder value) {
      return (
            FfiConverterTypeKeyRef.INSTANCE.allocationSize(value.signer()) +
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterString.INSTANCE.allocationSize(value.token()) +
            FfiConverterString.INSTANCE.allocationSize(value.wrappedToken()) +
            FfiConverterString.INSTANCE.allocationSize(value.amount()) +
            FfiConverterString.INSTANCE.allocationSize(value.minMinted()) +
            FfiConverterString.INSTANCE.allocationSize(value.minFill()) +
            FfiConverterString.INSTANCE.allocationSize(value.fee()) +
            FfiConverterString.INSTANCE.allocationSize(value.relayer()) +
            FfiConverterOptionalString.INSTANCE.allocationSize(value.destination()) +
            FfiConverterByte.INSTANCE.allocationSize(value.flags()) +
            FfiConverterString.INSTANCE.allocationSize(value.batch()) +
            FfiConverterOptionalString.INSTANCE.allocationSize(value.nonce()) +
            FfiConverterLong.INSTANCE.allocationSize(value.validUntil())
      );
  }

  @Override
  public void write(WrapOrder value, java.nio.ByteBuffer buf) {
      FfiConverterTypeKeyRef.INSTANCE.write(value.signer(), buf);
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterString.INSTANCE.write(value.token(), buf);
      FfiConverterString.INSTANCE.write(value.wrappedToken(), buf);
      FfiConverterString.INSTANCE.write(value.amount(), buf);
      FfiConverterString.INSTANCE.write(value.minMinted(), buf);
      FfiConverterString.INSTANCE.write(value.minFill(), buf);
      FfiConverterString.INSTANCE.write(value.fee(), buf);
      FfiConverterString.INSTANCE.write(value.relayer(), buf);
      FfiConverterOptionalString.INSTANCE.write(value.destination(), buf);
      FfiConverterByte.INSTANCE.write(value.flags(), buf);
      FfiConverterString.INSTANCE.write(value.batch(), buf);
      FfiConverterOptionalString.INSTANCE.write(value.nonce(), buf);
      FfiConverterLong.INSTANCE.write(value.validUntil(), buf);
  }
}



