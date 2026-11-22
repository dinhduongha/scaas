package uniffi.scaas_sdk;


public enum FfiConverterTypePqzBalanceRequest implements FfiConverterRustBuffer<PqzBalanceRequest> {
  INSTANCE;

  @Override
  public PqzBalanceRequest read(java.nio.ByteBuffer buf) {
    return new PqzBalanceRequest(
      FfiConverterTypeKeyRef.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterLong.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(PqzBalanceRequest value) {
      return (
            FfiConverterTypeKeyRef.INSTANCE.allocationSize(value.signer()) +
            FfiConverterString.INSTANCE.allocationSize(value.chain()) +
            FfiConverterString.INSTANCE.allocationSize(value.token()) +
            FfiConverterLong.INSTANCE.allocationSize(value.keyVersion())
      );
  }

  @Override
  public void write(PqzBalanceRequest value, java.nio.ByteBuffer buf) {
      FfiConverterTypeKeyRef.INSTANCE.write(value.signer(), buf);
      FfiConverterString.INSTANCE.write(value.chain(), buf);
      FfiConverterString.INSTANCE.write(value.token(), buf);
      FfiConverterLong.INSTANCE.write(value.keyVersion(), buf);
  }
}



