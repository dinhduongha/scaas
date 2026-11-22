package uniffi.scaas_sdk;


public enum FfiConverterTypeUaGrantRole implements FfiConverterRustBuffer<UaGrantRole> {
  INSTANCE;

  @Override
  public UaGrantRole read(java.nio.ByteBuffer buf) {
    return new UaGrantRole(
      FfiConverterTypeKeyRef.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterOptionalString.INSTANCE.read(buf),
      FfiConverterTypeEnvelope.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(UaGrantRole value) {
      return (
            FfiConverterTypeKeyRef.INSTANCE.allocationSize(value.signer()) +
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterString.INSTANCE.allocationSize(value.batch()) +
            FfiConverterString.INSTANCE.allocationSize(value.target()) +
            FfiConverterString.INSTANCE.allocationSize(value.bit()) +
            FfiConverterString.INSTANCE.allocationSize(value.account()) +
            FfiConverterOptionalString.INSTANCE.allocationSize(value.chainUid()) +
            FfiConverterTypeEnvelope.INSTANCE.allocationSize(value.envelope())
      );
  }

  @Override
  public void write(UaGrantRole value, java.nio.ByteBuffer buf) {
      FfiConverterTypeKeyRef.INSTANCE.write(value.signer(), buf);
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterString.INSTANCE.write(value.batch(), buf);
      FfiConverterString.INSTANCE.write(value.target(), buf);
      FfiConverterString.INSTANCE.write(value.bit(), buf);
      FfiConverterString.INSTANCE.write(value.account(), buf);
      FfiConverterOptionalString.INSTANCE.write(value.chainUid(), buf);
      FfiConverterTypeEnvelope.INSTANCE.write(value.envelope(), buf);
  }
}



