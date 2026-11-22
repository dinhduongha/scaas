package uniffi.scaas_sdk;

public enum FfiConverterOptionalTypeGasPerItem implements FfiConverterRustBuffer<GasPerItem> {
  INSTANCE;

  @Override
  public GasPerItem read(java.nio.ByteBuffer buf) {
    if (buf.get() == (byte)0) {
      return null;
    }
    return FfiConverterTypeGasPerItem.INSTANCE.read(buf);
  }

  @Override
  public long allocationSize(GasPerItem value) {
    if (value == null) {
      return 1L;
    } else {
      return 1L + FfiConverterTypeGasPerItem.INSTANCE.allocationSize(value);
    }
  }

  @Override
  public void write(GasPerItem value, java.nio.ByteBuffer buf) {
    if (value == null) {
      buf.put((byte)0);
    } else {
      buf.put((byte)1);
      FfiConverterTypeGasPerItem.INSTANCE.write(value, buf);
    }
  }
}



