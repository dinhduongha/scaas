package uniffi.scaas_sdk;


public enum FfiConverterTypeUaSetWrapLimits implements FfiConverterRustBuffer<UaSetWrapLimits> {
  INSTANCE;

  @Override
  public UaSetWrapLimits read(java.nio.ByteBuffer buf) {
    return new UaSetWrapLimits(
      FfiConverterTypeKeyRef.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterBoolean.INSTANCE.read(buf),
      FfiConverterBoolean.INSTANCE.read(buf),
      FfiConverterBoolean.INSTANCE.read(buf),
      FfiConverterOptionalString.INSTANCE.read(buf),
      FfiConverterTypeEnvelope.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(UaSetWrapLimits value) {
      return (
            FfiConverterTypeKeyRef.INSTANCE.allocationSize(value.signer()) +
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterString.INSTANCE.allocationSize(value.batch()) +
            FfiConverterString.INSTANCE.allocationSize(value.target()) +
            FfiConverterString.INSTANCE.allocationSize(value.legs()) +
            FfiConverterBoolean.INSTANCE.allocationSize(value.netUnwrap()) +
            FfiConverterBoolean.INSTANCE.allocationSize(value.wrapList()) +
            FfiConverterBoolean.INSTANCE.allocationSize(value.unwrapList()) +
            FfiConverterOptionalString.INSTANCE.allocationSize(value.chainUid()) +
            FfiConverterTypeEnvelope.INSTANCE.allocationSize(value.envelope())
      );
  }

  @Override
  public void write(UaSetWrapLimits value, java.nio.ByteBuffer buf) {
      FfiConverterTypeKeyRef.INSTANCE.write(value.signer(), buf);
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterString.INSTANCE.write(value.batch(), buf);
      FfiConverterString.INSTANCE.write(value.target(), buf);
      FfiConverterString.INSTANCE.write(value.legs(), buf);
      FfiConverterBoolean.INSTANCE.write(value.netUnwrap(), buf);
      FfiConverterBoolean.INSTANCE.write(value.wrapList(), buf);
      FfiConverterBoolean.INSTANCE.write(value.unwrapList(), buf);
      FfiConverterOptionalString.INSTANCE.write(value.chainUid(), buf);
      FfiConverterTypeEnvelope.INSTANCE.write(value.envelope(), buf);
  }
}



