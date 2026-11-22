package uniffi.scaas_sdk;


public enum FfiConverterTypeDelegateRevoke implements FfiConverterRustBuffer<DelegateRevoke> {
  INSTANCE;

  @Override
  public DelegateRevoke read(java.nio.ByteBuffer buf) {
    return new DelegateRevoke(
      FfiConverterTypeKeyRef.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterTypeEnvelope.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(DelegateRevoke value) {
      return (
            FfiConverterTypeKeyRef.INSTANCE.allocationSize(value.signer()) +
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterString.INSTANCE.allocationSize(value.contract()) +
            FfiConverterString.INSTANCE.allocationSize(value.batch()) +
            FfiConverterString.INSTANCE.allocationSize(value.token()) +
            FfiConverterString.INSTANCE.allocationSize(value.epoch()) +
            FfiConverterTypeEnvelope.INSTANCE.allocationSize(value.envelope())
      );
  }

  @Override
  public void write(DelegateRevoke value, java.nio.ByteBuffer buf) {
      FfiConverterTypeKeyRef.INSTANCE.write(value.signer(), buf);
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterString.INSTANCE.write(value.contract(), buf);
      FfiConverterString.INSTANCE.write(value.batch(), buf);
      FfiConverterString.INSTANCE.write(value.token(), buf);
      FfiConverterString.INSTANCE.write(value.epoch(), buf);
      FfiConverterTypeEnvelope.INSTANCE.write(value.envelope(), buf);
  }
}



