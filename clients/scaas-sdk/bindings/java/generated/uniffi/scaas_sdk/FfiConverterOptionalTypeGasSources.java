package uniffi.scaas_sdk;

public enum FfiConverterOptionalTypeGasSources implements FfiConverterRustBuffer<GasSources> {
  INSTANCE;

  @Override
  public GasSources read(java.nio.ByteBuffer buf) {
    if (buf.get() == (byte)0) {
      return null;
    }
    return FfiConverterTypeGasSources.INSTANCE.read(buf);
  }

  @Override
  public long allocationSize(GasSources value) {
    if (value == null) {
      return 1L;
    } else {
      return 1L + FfiConverterTypeGasSources.INSTANCE.allocationSize(value);
    }
  }

  @Override
  public void write(GasSources value, java.nio.ByteBuffer buf) {
    if (value == null) {
      buf.put((byte)0);
    } else {
      buf.put((byte)1);
      FfiConverterTypeGasSources.INSTANCE.write(value, buf);
    }
  }
}



