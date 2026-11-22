package uniffi.scaas_sdk;

public enum FfiConverterOptionalTypeKeyRef implements FfiConverterRustBuffer<KeyRef> {
  INSTANCE;

  @Override
  public KeyRef read(java.nio.ByteBuffer buf) {
    if (buf.get() == (byte)0) {
      return null;
    }
    return FfiConverterTypeKeyRef.INSTANCE.read(buf);
  }

  @Override
  public long allocationSize(KeyRef value) {
    if (value == null) {
      return 1L;
    } else {
      return 1L + FfiConverterTypeKeyRef.INSTANCE.allocationSize(value);
    }
  }

  @Override
  public void write(KeyRef value, java.nio.ByteBuffer buf) {
    if (value == null) {
      buf.put((byte)0);
    } else {
      buf.put((byte)1);
      FfiConverterTypeKeyRef.INSTANCE.write(value, buf);
    }
  }
}



