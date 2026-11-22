package uniffi.scaas_sdk;


public enum FfiConverterTypeSmartOp implements FfiConverterRustBuffer<SmartOp> {
  INSTANCE;

  @Override
  public SmartOp read(java.nio.ByteBuffer buf) {
    return new SmartOp(
      FfiConverterTypeKeyRef.INSTANCE.read(buf),
      FfiConverterOptionalString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterTypeEnvelope.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(SmartOp value) {
      return (
            FfiConverterTypeKeyRef.INSTANCE.allocationSize(value.signer()) +
            FfiConverterOptionalString.INSTANCE.allocationSize(value.keyIndex()) +
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterString.INSTANCE.allocationSize(value.account()) +
            FfiConverterString.INSTANCE.allocationSize(value.batch()) +
            FfiConverterTypeEnvelope.INSTANCE.allocationSize(value.envelope())
      );
  }

  @Override
  public void write(SmartOp value, java.nio.ByteBuffer buf) {
      FfiConverterTypeKeyRef.INSTANCE.write(value.signer(), buf);
      FfiConverterOptionalString.INSTANCE.write(value.keyIndex(), buf);
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterString.INSTANCE.write(value.account(), buf);
      FfiConverterString.INSTANCE.write(value.batch(), buf);
      FfiConverterTypeEnvelope.INSTANCE.write(value.envelope(), buf);
  }
}



