package uniffi.scaas_sdk;


public enum FfiConverterTypeUaApproveRelease implements FfiConverterRustBuffer<UaApproveRelease> {
  INSTANCE;

  @Override
  public UaApproveRelease read(java.nio.ByteBuffer buf) {
    return new UaApproveRelease(
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
  public long allocationSize(UaApproveRelease value) {
      return (
            FfiConverterTypeKeyRef.INSTANCE.allocationSize(value.signer()) +
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterString.INSTANCE.allocationSize(value.batch()) +
            FfiConverterString.INSTANCE.allocationSize(value.target()) +
            FfiConverterString.INSTANCE.allocationSize(value.contractClass()) +
            FfiConverterString.INSTANCE.allocationSize(value.kind()) +
            FfiConverterString.INSTANCE.allocationSize(value.version()) +
            FfiConverterString.INSTANCE.allocationSize(value.envVersion()) +
            FfiConverterString.INSTANCE.allocationSize(value.initSelector()) +
            FfiConverterString.INSTANCE.allocationSize(value.interfaceId()) +
            FfiConverterString.INSTANCE.allocationSize(value.initcodeHash()) +
            FfiConverterString.INSTANCE.allocationSize(value.implArgsHash()) +
            FfiConverterString.INSTANCE.allocationSize(value.factory()) +
            FfiConverterString.INSTANCE.allocationSize(value.adminGeneration()) +
            FfiConverterString.INSTANCE.allocationSize(value.until()) +
            FfiConverterOptionalString.INSTANCE.allocationSize(value.chainUid()) +
            FfiConverterTypeEnvelope.INSTANCE.allocationSize(value.envelope())
      );
  }

  @Override
  public void write(UaApproveRelease value, java.nio.ByteBuffer buf) {
      FfiConverterTypeKeyRef.INSTANCE.write(value.signer(), buf);
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterString.INSTANCE.write(value.batch(), buf);
      FfiConverterString.INSTANCE.write(value.target(), buf);
      FfiConverterString.INSTANCE.write(value.contractClass(), buf);
      FfiConverterString.INSTANCE.write(value.kind(), buf);
      FfiConverterString.INSTANCE.write(value.version(), buf);
      FfiConverterString.INSTANCE.write(value.envVersion(), buf);
      FfiConverterString.INSTANCE.write(value.initSelector(), buf);
      FfiConverterString.INSTANCE.write(value.interfaceId(), buf);
      FfiConverterString.INSTANCE.write(value.initcodeHash(), buf);
      FfiConverterString.INSTANCE.write(value.implArgsHash(), buf);
      FfiConverterString.INSTANCE.write(value.factory(), buf);
      FfiConverterString.INSTANCE.write(value.adminGeneration(), buf);
      FfiConverterString.INSTANCE.write(value.until(), buf);
      FfiConverterOptionalString.INSTANCE.write(value.chainUid(), buf);
      FfiConverterTypeEnvelope.INSTANCE.write(value.envelope(), buf);
  }
}



