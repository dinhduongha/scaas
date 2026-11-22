package uniffi.scaas_sdk;

public enum FfiConverterOptionalTypeGasPerByte implements FfiConverterRustBuffer<GasPerByte> {
  INSTANCE;

  @Override
  public GasPerByte read(java.nio.ByteBuffer buf) {
    if (buf.get() == (byte)0) {
      return null;
    }
    return FfiConverterTypeGasPerByte.INSTANCE.read(buf);
  }

  @Override
  public long allocationSize(GasPerByte value) {
    if (value == null) {
      return 1L;
    } else {
      return 1L + FfiConverterTypeGasPerByte.INSTANCE.allocationSize(value);
    }
  }

  @Override
  public void write(GasPerByte value, java.nio.ByteBuffer buf) {
    if (value == null) {
      buf.put((byte)0);
    } else {
      buf.put((byte)1);
      FfiConverterTypeGasPerByte.INSTANCE.write(value, buf);
    }
  }
}



