package uniffi.scaas_sdk;


public enum FfiConverterTypeConfirmRemove implements FfiConverterRustBuffer<ConfirmRemove> {
  INSTANCE;

  @Override
  public ConfirmRemove read(java.nio.ByteBuffer buf) {
    return new ConfirmRemove();
  }

  @Override
  public long allocationSize(ConfirmRemove value) {
      return 0L;
  }

  @Override
  public void write(ConfirmRemove value, java.nio.ByteBuffer buf) {
  }
}



