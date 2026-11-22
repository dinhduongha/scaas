package uniffi.scaas_sdk;


public enum FfiConverterTypeZetherWrapShield implements FfiConverterRustBuffer<ZetherWrapShield> {
  INSTANCE;

  @Override
  public ZetherWrapShield read(java.nio.ByteBuffer buf) {
    return new ZetherWrapShield(
      FfiConverterTypeKeyRef.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterTypeEnvelope.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(ZetherWrapShield value) {
      return (
            FfiConverterTypeKeyRef.INSTANCE.allocationSize(value.signer()) +
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterString.INSTANCE.allocationSize(value.token()) +
            FfiConverterString.INSTANCE.allocationSize(value.batch()) +
            FfiConverterString.INSTANCE.allocationSize(value.underlying()) +
            FfiConverterString.INSTANCE.allocationSize(value.amountIn()) +
            FfiConverterString.INSTANCE.allocationSize(value.toUa()) +
            FfiConverterTypeEnvelope.INSTANCE.allocationSize(value.envelope())
      );
  }

  @Override
  public void write(ZetherWrapShield value, java.nio.ByteBuffer buf) {
      FfiConverterTypeKeyRef.INSTANCE.write(value.signer(), buf);
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterString.INSTANCE.write(value.token(), buf);
      FfiConverterString.INSTANCE.write(value.batch(), buf);
      FfiConverterString.INSTANCE.write(value.underlying(), buf);
      FfiConverterString.INSTANCE.write(value.amountIn(), buf);
      FfiConverterString.INSTANCE.write(value.toUa(), buf);
      FfiConverterTypeEnvelope.INSTANCE.write(value.envelope(), buf);
  }
}



