package uniffi.scaas_sdk;


public enum FfiConverterTypeRescueVault implements FfiConverterRustBuffer<RescueVault> {
  INSTANCE;

  @Override
  public RescueVault read(java.nio.ByteBuffer buf) {
    return new RescueVault(
      FfiConverterTypeKeyRef.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterTypeRescueOp.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(RescueVault value) {
      return (
            FfiConverterTypeKeyRef.INSTANCE.allocationSize(value.signer()) +
            FfiConverterString.INSTANCE.allocationSize(value.vault()) +
            FfiConverterTypeRescueOp.INSTANCE.allocationSize(value.op())
      );
  }

  @Override
  public void write(RescueVault value, java.nio.ByteBuffer buf) {
      FfiConverterTypeKeyRef.INSTANCE.write(value.signer(), buf);
      FfiConverterString.INSTANCE.write(value.vault(), buf);
      FfiConverterTypeRescueOp.INSTANCE.write(value.op(), buf);
  }
}



