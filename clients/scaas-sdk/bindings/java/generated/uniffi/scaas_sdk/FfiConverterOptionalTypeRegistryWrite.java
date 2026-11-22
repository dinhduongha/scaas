package uniffi.scaas_sdk;

public enum FfiConverterOptionalTypeRegistryWrite implements FfiConverterRustBuffer<RegistryWrite> {
  INSTANCE;

  @Override
  public RegistryWrite read(java.nio.ByteBuffer buf) {
    if (buf.get() == (byte)0) {
      return null;
    }
    return FfiConverterTypeRegistryWrite.INSTANCE.read(buf);
  }

  @Override
  public long allocationSize(RegistryWrite value) {
    if (value == null) {
      return 1L;
    } else {
      return 1L + FfiConverterTypeRegistryWrite.INSTANCE.allocationSize(value);
    }
  }

  @Override
  public void write(RegistryWrite value, java.nio.ByteBuffer buf) {
    if (value == null) {
      buf.put((byte)0);
    } else {
      buf.put((byte)1);
      FfiConverterTypeRegistryWrite.INSTANCE.write(value, buf);
    }
  }
}



