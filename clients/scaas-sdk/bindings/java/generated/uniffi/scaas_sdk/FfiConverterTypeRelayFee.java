package uniffi.scaas_sdk;


public enum FfiConverterTypeRelayFee implements FfiConverterRustBuffer<RelayFee> {
  INSTANCE;

  @Override
  public RelayFee read(java.nio.ByteBuffer buf) {
    return new RelayFee(
      FfiConverterTypeKeyRef.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(RelayFee value) {
      return (
            FfiConverterTypeKeyRef.INSTANCE.allocationSize(value.signer()) +
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterString.INSTANCE.allocationSize(value.token()) +
            FfiConverterString.INSTANCE.allocationSize(value.call()) +
            FfiConverterString.INSTANCE.allocationSize(value.payee()) +
            FfiConverterString.INSTANCE.allocationSize(value.value()) +
            FfiConverterString.INSTANCE.allocationSize(value.batch()) +
            FfiConverterLong.INSTANCE.allocationSize(value.validUntil()) +
            FfiConverterString.INSTANCE.allocationSize(value.relayer())
      );
  }

  @Override
  public void write(RelayFee value, java.nio.ByteBuffer buf) {
      FfiConverterTypeKeyRef.INSTANCE.write(value.signer(), buf);
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterString.INSTANCE.write(value.token(), buf);
      FfiConverterString.INSTANCE.write(value.call(), buf);
      FfiConverterString.INSTANCE.write(value.payee(), buf);
      FfiConverterString.INSTANCE.write(value.value(), buf);
      FfiConverterString.INSTANCE.write(value.batch(), buf);
      FfiConverterLong.INSTANCE.write(value.validUntil(), buf);
      FfiConverterString.INSTANCE.write(value.relayer(), buf);
  }
}



