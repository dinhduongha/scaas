package uniffi.scaas_sdk;


public enum FfiConverterTypeUaSetFeeSplit implements FfiConverterRustBuffer<UaSetFeeSplit> {
  INSTANCE;

  @Override
  public UaSetFeeSplit read(java.nio.ByteBuffer buf) {
    return new UaSetFeeSplit(
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
  public long allocationSize(UaSetFeeSplit value) {
      return (
            FfiConverterTypeKeyRef.INSTANCE.allocationSize(value.signer()) +
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterString.INSTANCE.allocationSize(value.batch()) +
            FfiConverterString.INSTANCE.allocationSize(value.target()) +
            FfiConverterString.INSTANCE.allocationSize(value.relayerSharePpm()) +
            FfiConverterString.INSTANCE.allocationSize(value.treasury()) +
            FfiConverterOptionalString.INSTANCE.allocationSize(value.chainUid()) +
            FfiConverterTypeEnvelope.INSTANCE.allocationSize(value.envelope())
      );
  }

  @Override
  public void write(UaSetFeeSplit value, java.nio.ByteBuffer buf) {
      FfiConverterTypeKeyRef.INSTANCE.write(value.signer(), buf);
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterString.INSTANCE.write(value.batch(), buf);
      FfiConverterString.INSTANCE.write(value.target(), buf);
      FfiConverterString.INSTANCE.write(value.relayerSharePpm(), buf);
      FfiConverterString.INSTANCE.write(value.treasury(), buf);
      FfiConverterOptionalString.INSTANCE.write(value.chainUid(), buf);
      FfiConverterTypeEnvelope.INSTANCE.write(value.envelope(), buf);
  }
}



