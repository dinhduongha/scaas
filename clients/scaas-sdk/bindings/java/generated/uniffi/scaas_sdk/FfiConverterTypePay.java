package uniffi.scaas_sdk;


public enum FfiConverterTypePay implements FfiConverterRustBuffer<Pay> {
  INSTANCE;

  @Override
  public Pay read(java.nio.ByteBuffer buf) {
    return new Pay(
      FfiConverterTypeKeyRef.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterTypePayMeta.INSTANCE.read(buf),
      FfiConverterTypeEnvelope.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(Pay value) {
      return (
            FfiConverterTypeKeyRef.INSTANCE.allocationSize(value.signer()) +
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterString.INSTANCE.allocationSize(value.token()) +
            FfiConverterString.INSTANCE.allocationSize(value.to()) +
            FfiConverterString.INSTANCE.allocationSize(value.value()) +
            FfiConverterTypePayMeta.INSTANCE.allocationSize(value.meta()) +
            FfiConverterTypeEnvelope.INSTANCE.allocationSize(value.envelope())
      );
  }

  @Override
  public void write(Pay value, java.nio.ByteBuffer buf) {
      FfiConverterTypeKeyRef.INSTANCE.write(value.signer(), buf);
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterString.INSTANCE.write(value.token(), buf);
      FfiConverterString.INSTANCE.write(value.to(), buf);
      FfiConverterString.INSTANCE.write(value.value(), buf);
      FfiConverterTypePayMeta.INSTANCE.write(value.meta(), buf);
      FfiConverterTypeEnvelope.INSTANCE.write(value.envelope(), buf);
  }
}



