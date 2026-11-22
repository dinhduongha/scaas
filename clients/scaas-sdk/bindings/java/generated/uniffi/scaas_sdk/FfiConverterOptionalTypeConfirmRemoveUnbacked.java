package uniffi.scaas_sdk;

public enum FfiConverterOptionalTypeConfirmRemoveUnbacked implements FfiConverterRustBuffer<ConfirmRemoveUnbacked> {
  INSTANCE;

  @Override
  public ConfirmRemoveUnbacked read(java.nio.ByteBuffer buf) {
    if (buf.get() == (byte)0) {
      return null;
    }
    return FfiConverterTypeConfirmRemoveUnbacked.INSTANCE.read(buf);
  }

  @Override
  public long allocationSize(ConfirmRemoveUnbacked value) {
    if (value == null) {
      return 1L;
    } else {
      return 1L + FfiConverterTypeConfirmRemoveUnbacked.INSTANCE.allocationSize(value);
    }
  }

  @Override
  public void write(ConfirmRemoveUnbacked value, java.nio.ByteBuffer buf) {
    if (value == null) {
      buf.put((byte)0);
    } else {
      buf.put((byte)1);
      FfiConverterTypeConfirmRemoveUnbacked.INSTANCE.write(value, buf);
    }
  }
}



