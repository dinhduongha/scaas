package uniffi.scaas_sdk;


public enum FfiConverterTypePayWithTax implements FfiConverterRustBuffer<PayWithTax> {
  INSTANCE;

  @Override
  public PayWithTax read(java.nio.ByteBuffer buf) {
    return new PayWithTax(
      FfiConverterTypeKeyRef.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterTypePayMeta.INSTANCE.read(buf),
      FfiConverterByte.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterTypeEnvelope.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(PayWithTax value) {
      return (
            FfiConverterTypeKeyRef.INSTANCE.allocationSize(value.signer()) +
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterString.INSTANCE.allocationSize(value.token()) +
            FfiConverterString.INSTANCE.allocationSize(value.to()) +
            FfiConverterString.INSTANCE.allocationSize(value.value()) +
            FfiConverterTypePayMeta.INSTANCE.allocationSize(value.meta()) +
            FfiConverterByte.INSTANCE.allocationSize(value.taxMode()) +
            FfiConverterString.INSTANCE.allocationSize(value.tax()) +
            FfiConverterTypeEnvelope.INSTANCE.allocationSize(value.envelope())
      );
  }

  @Override
  public void write(PayWithTax value, java.nio.ByteBuffer buf) {
      FfiConverterTypeKeyRef.INSTANCE.write(value.signer(), buf);
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterString.INSTANCE.write(value.token(), buf);
      FfiConverterString.INSTANCE.write(value.to(), buf);
      FfiConverterString.INSTANCE.write(value.value(), buf);
      FfiConverterTypePayMeta.INSTANCE.write(value.meta(), buf);
      FfiConverterByte.INSTANCE.write(value.taxMode(), buf);
      FfiConverterString.INSTANCE.write(value.tax(), buf);
      FfiConverterTypeEnvelope.INSTANCE.write(value.envelope(), buf);
  }
}



