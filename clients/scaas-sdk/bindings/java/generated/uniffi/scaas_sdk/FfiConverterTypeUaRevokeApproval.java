package uniffi.scaas_sdk;


public enum FfiConverterTypeUaRevokeApproval implements FfiConverterRustBuffer<UaRevokeApproval> {
  INSTANCE;

  @Override
  public UaRevokeApproval read(java.nio.ByteBuffer buf) {
    return new UaRevokeApproval(
      FfiConverterTypeKeyRef.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterOptionalString.INSTANCE.read(buf),
      FfiConverterTypeEnvelope.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(UaRevokeApproval value) {
      return (
            FfiConverterTypeKeyRef.INSTANCE.allocationSize(value.signer()) +
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterString.INSTANCE.allocationSize(value.batch()) +
            FfiConverterString.INSTANCE.allocationSize(value.target()) +
            FfiConverterString.INSTANCE.allocationSize(value.key()) +
            FfiConverterOptionalString.INSTANCE.allocationSize(value.chainUid()) +
            FfiConverterTypeEnvelope.INSTANCE.allocationSize(value.envelope())
      );
  }

  @Override
  public void write(UaRevokeApproval value, java.nio.ByteBuffer buf) {
      FfiConverterTypeKeyRef.INSTANCE.write(value.signer(), buf);
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterString.INSTANCE.write(value.batch(), buf);
      FfiConverterString.INSTANCE.write(value.target(), buf);
      FfiConverterString.INSTANCE.write(value.key(), buf);
      FfiConverterOptionalString.INSTANCE.write(value.chainUid(), buf);
      FfiConverterTypeEnvelope.INSTANCE.write(value.envelope(), buf);
  }
}



