package uniffi.scaas_sdk;

public enum FfiConverterOptionalTypeL1Fee implements FfiConverterRustBuffer<L1Fee> {
  INSTANCE;

  @Override
  public L1Fee read(java.nio.ByteBuffer buf) {
    if (buf.get() == (byte)0) {
      return null;
    }
    return FfiConverterTypeL1Fee.INSTANCE.read(buf);
  }

  @Override
  public long allocationSize(L1Fee value) {
    if (value == null) {
      return 1L;
    } else {
      return 1L + FfiConverterTypeL1Fee.INSTANCE.allocationSize(value);
    }
  }

  @Override
  public void write(L1Fee value, java.nio.ByteBuffer buf) {
    if (value == null) {
      buf.put((byte)0);
    } else {
      buf.put((byte)1);
      FfiConverterTypeL1Fee.INSTANCE.write(value, buf);
    }
  }
}



