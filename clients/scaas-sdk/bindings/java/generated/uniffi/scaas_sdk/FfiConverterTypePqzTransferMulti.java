package uniffi.scaas_sdk;


public enum FfiConverterTypePqzTransferMulti implements FfiConverterRustBuffer<PqzTransferMulti> {
  INSTANCE;

  @Override
  public PqzTransferMulti read(java.nio.ByteBuffer buf) {
    return new PqzTransferMulti(
      FfiConverterTypeKeyRef.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf),
      FfiConverterSequenceTypePqzLeg.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf),
      FfiConverterTypeEnvelope.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(PqzTransferMulti value) {
      return (
            FfiConverterTypeKeyRef.INSTANCE.allocationSize(value.signer()) +
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterString.INSTANCE.allocationSize(value.token()) +
            FfiConverterString.INSTANCE.allocationSize(value.batch()) +
            FfiConverterLong.INSTANCE.allocationSize(value.keyVersion()) +
            FfiConverterSequenceTypePqzLeg.INSTANCE.allocationSize(value.legs()) +
            FfiConverterString.INSTANCE.allocationSize(value.decoyFee()) +
            FfiConverterLong.INSTANCE.allocationSize(value.validUntilBlock()) +
            FfiConverterTypeEnvelope.INSTANCE.allocationSize(value.envelope())
      );
  }

  @Override
  public void write(PqzTransferMulti value, java.nio.ByteBuffer buf) {
      FfiConverterTypeKeyRef.INSTANCE.write(value.signer(), buf);
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterString.INSTANCE.write(value.token(), buf);
      FfiConverterString.INSTANCE.write(value.batch(), buf);
      FfiConverterLong.INSTANCE.write(value.keyVersion(), buf);
      FfiConverterSequenceTypePqzLeg.INSTANCE.write(value.legs(), buf);
      FfiConverterString.INSTANCE.write(value.decoyFee(), buf);
      FfiConverterLong.INSTANCE.write(value.validUntilBlock(), buf);
      FfiConverterTypeEnvelope.INSTANCE.write(value.envelope(), buf);
  }
}



