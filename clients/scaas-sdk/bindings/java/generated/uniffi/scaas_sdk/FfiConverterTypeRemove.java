package uniffi.scaas_sdk;


public enum FfiConverterTypeRemove implements FfiConverterRustBuffer<Remove> {
  INSTANCE;

  @Override
  public Remove read(java.nio.ByteBuffer buf) {
    return new Remove(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterTypeConfirmRemove.INSTANCE.read(buf),
      FfiConverterOptionalTypeConfirmRemoveUnbacked.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(Remove value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.seed()) +
            FfiConverterTypeConfirmRemove.INSTANCE.allocationSize(value.confirm()) +
            FfiConverterOptionalTypeConfirmRemoveUnbacked.INSTANCE.allocationSize(value.unbacked())
      );
  }

  @Override
  public void write(Remove value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.seed(), buf);
      FfiConverterTypeConfirmRemove.INSTANCE.write(value.confirm(), buf);
      FfiConverterOptionalTypeConfirmRemoveUnbacked.INSTANCE.write(value.unbacked(), buf);
  }
}



