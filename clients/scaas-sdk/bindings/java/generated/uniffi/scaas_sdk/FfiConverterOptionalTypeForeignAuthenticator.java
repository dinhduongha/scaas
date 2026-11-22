package uniffi.scaas_sdk;

public enum FfiConverterOptionalTypeForeignAuthenticator implements FfiConverterRustBuffer<ForeignAuthenticator> {
  INSTANCE;

  @Override
  public ForeignAuthenticator read(java.nio.ByteBuffer buf) {
    if (buf.get() == (byte)0) {
      return null;
    }
    return FfiConverterTypeForeignAuthenticator.INSTANCE.read(buf);
  }

  @Override
  public long allocationSize(ForeignAuthenticator value) {
    if (value == null) {
      return 1L;
    } else {
      return 1L + FfiConverterTypeForeignAuthenticator.INSTANCE.allocationSize(value);
    }
  }

  @Override
  public void write(ForeignAuthenticator value, java.nio.ByteBuffer buf) {
    if (value == null) {
      buf.put((byte)0);
    } else {
      buf.put((byte)1);
      FfiConverterTypeForeignAuthenticator.INSTANCE.write(value, buf);
    }
  }
}



