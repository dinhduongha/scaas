package uniffi.scaas_sdk;


public enum FfiConverterTypePayeeFee implements FfiConverterRustBuffer<PayeeFee> {
  INSTANCE;

  @Override
  public PayeeFee read(java.nio.ByteBuffer buf) {
    return new PayeeFee(
      FfiConverterTypeKeyRef.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterTypePayment.INSTANCE.read(buf),
      FfiConverterTypePayMeta.INSTANCE.read(buf),
      FfiConverterTypePayerAuth.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(PayeeFee value) {
      return (
            FfiConverterTypeKeyRef.INSTANCE.allocationSize(value.signer()) +
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterString.INSTANCE.allocationSize(value.token()) +
            FfiConverterTypePayment.INSTANCE.allocationSize(value.payment()) +
            FfiConverterTypePayMeta.INSTANCE.allocationSize(value.meta()) +
            FfiConverterTypePayerAuth.INSTANCE.allocationSize(value.payerAuth()) +
            FfiConverterString.INSTANCE.allocationSize(value.fee()) +
            FfiConverterString.INSTANCE.allocationSize(value.feeRecipient()) +
            FfiConverterLong.INSTANCE.allocationSize(value.validUntil())
      );
  }

  @Override
  public void write(PayeeFee value, java.nio.ByteBuffer buf) {
      FfiConverterTypeKeyRef.INSTANCE.write(value.signer(), buf);
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterString.INSTANCE.write(value.token(), buf);
      FfiConverterTypePayment.INSTANCE.write(value.payment(), buf);
      FfiConverterTypePayMeta.INSTANCE.write(value.meta(), buf);
      FfiConverterTypePayerAuth.INSTANCE.write(value.payerAuth(), buf);
      FfiConverterString.INSTANCE.write(value.fee(), buf);
      FfiConverterString.INSTANCE.write(value.feeRecipient(), buf);
      FfiConverterLong.INSTANCE.write(value.validUntil(), buf);
  }
}



