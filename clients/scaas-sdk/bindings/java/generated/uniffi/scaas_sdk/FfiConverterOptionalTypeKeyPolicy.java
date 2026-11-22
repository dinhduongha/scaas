package uniffi.scaas_sdk;

public enum FfiConverterOptionalTypeKeyPolicy implements FfiConverterRustBuffer<KeyPolicy> {
  INSTANCE;

  @Override
  public KeyPolicy read(java.nio.ByteBuffer buf) {
    if (buf.get() == (byte)0) {
      return null;
    }
    return FfiConverterTypeKeyPolicy.INSTANCE.read(buf);
  }

  @Override
  public long allocationSize(KeyPolicy value) {
    if (value == null) {
      return 1L;
    } else {
      return 1L + FfiConverterTypeKeyPolicy.INSTANCE.allocationSize(value);
    }
  }

  @Override
  public void write(KeyPolicy value, java.nio.ByteBuffer buf) {
    if (value == null) {
      buf.put((byte)0);
    } else {
      buf.put((byte)1);
      FfiConverterTypeKeyPolicy.INSTANCE.write(value, buf);
    }
  }
}



