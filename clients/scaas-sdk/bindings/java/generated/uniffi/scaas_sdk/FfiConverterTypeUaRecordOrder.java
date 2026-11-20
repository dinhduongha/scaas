package uniffi.scaas_sdk;


public enum FfiConverterTypeUaRecordOrder implements FfiConverterRustBuffer<UaRecordOrder> {
  INSTANCE;

  @Override
  public UaRecordOrder read(java.nio.ByteBuffer buf) {
    return new UaRecordOrder(
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
      FfiConverterOptionalString.INSTANCE.read(buf),
      FfiConverterTypeEnvelope.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(UaRecordOrder value) {
      return (
            FfiConverterTypeKeyRef.INSTANCE.allocationSize(value.signer()) +
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterString.INSTANCE.allocationSize(value.batch()) +
            FfiConverterString.INSTANCE.allocationSize(value.target()) +
            FfiConverterString.INSTANCE.allocationSize(value.orderId()) +
            FfiConverterString.INSTANCE.allocationSize(value.documentHash()) +
            FfiConverterString.INSTANCE.allocationSize(value.subject()) +
            FfiConverterString.INSTANCE.allocationSize(value.beneficiary()) +
            FfiConverterString.INSTANCE.allocationSize(value.maxAmount()) +
            FfiConverterString.INSTANCE.allocationSize(value.freezeUntil()) +
            FfiConverterOptionalString.INSTANCE.allocationSize(value.chainUid()) +
            FfiConverterTypeEnvelope.INSTANCE.allocationSize(value.envelope())
      );
  }

  @Override
  public void write(UaRecordOrder value, java.nio.ByteBuffer buf) {
      FfiConverterTypeKeyRef.INSTANCE.write(value.signer(), buf);
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterString.INSTANCE.write(value.batch(), buf);
      FfiConverterString.INSTANCE.write(value.target(), buf);
      FfiConverterString.INSTANCE.write(value.orderId(), buf);
      FfiConverterString.INSTANCE.write(value.documentHash(), buf);
      FfiConverterString.INSTANCE.write(value.subject(), buf);
      FfiConverterString.INSTANCE.write(value.beneficiary(), buf);
      FfiConverterString.INSTANCE.write(value.maxAmount(), buf);
      FfiConverterString.INSTANCE.write(value.freezeUntil(), buf);
      FfiConverterOptionalString.INSTANCE.write(value.chainUid(), buf);
      FfiConverterTypeEnvelope.INSTANCE.write(value.envelope(), buf);
  }
}



