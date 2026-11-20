package uniffi.scaas_sdk;


public enum FfiConverterTypeConfirmRemoveUnbacked implements FfiConverterRustBuffer<ConfirmRemoveUnbacked> {
  INSTANCE;

  @Override
  public ConfirmRemoveUnbacked read(java.nio.ByteBuffer buf) {
    return new ConfirmRemoveUnbacked();
  }

  @Override
  public long allocationSize(ConfirmRemoveUnbacked value) {
      return 0L;
  }

  @Override
  public void write(ConfirmRemoveUnbacked value, java.nio.ByteBuffer buf) {
  }
}



