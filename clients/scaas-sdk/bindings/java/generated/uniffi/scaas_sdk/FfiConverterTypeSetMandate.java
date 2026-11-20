package uniffi.scaas_sdk;


public enum FfiConverterTypeSetMandate implements FfiConverterRustBuffer<SetMandate> {
  INSTANCE;

  @Override
  public SetMandate read(java.nio.ByteBuffer buf) {
    return new SetMandate(
      FfiConverterTypeKeyRef.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
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
  public long allocationSize(SetMandate value) {
      return (
            FfiConverterTypeKeyRef.INSTANCE.allocationSize(value.signer()) +
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterString.INSTANCE.allocationSize(value.contract()) +
            FfiConverterString.INSTANCE.allocationSize(value.batch()) +
            FfiConverterString.INSTANCE.allocationSize(value.token()) +
            FfiConverterString.INSTANCE.allocationSize(value.delegate()) +
            FfiConverterString.INSTANCE.allocationSize(value.maxPerPayment()) +
            FfiConverterString.INSTANCE.allocationSize(value.maxPerPeriod()) +
            FfiConverterString.INSTANCE.allocationSize(value.periodSeconds()) +
            FfiConverterString.INSTANCE.allocationSize(value.expiry()) +
            FfiConverterTypeEnvelope.INSTANCE.allocationSize(value.envelope())
      );
  }

  @Override
  public void write(SetMandate value, java.nio.ByteBuffer buf) {
      FfiConverterTypeKeyRef.INSTANCE.write(value.signer(), buf);
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterString.INSTANCE.write(value.contract(), buf);
      FfiConverterString.INSTANCE.write(value.batch(), buf);
      FfiConverterString.INSTANCE.write(value.token(), buf);
      FfiConverterString.INSTANCE.write(value.delegate(), buf);
      FfiConverterString.INSTANCE.write(value.maxPerPayment(), buf);
      FfiConverterString.INSTANCE.write(value.maxPerPeriod(), buf);
      FfiConverterString.INSTANCE.write(value.periodSeconds(), buf);
      FfiConverterString.INSTANCE.write(value.expiry(), buf);
      FfiConverterTypeEnvelope.INSTANCE.write(value.envelope(), buf);
  }
}



