package uniffi.scaas_sdk;

public enum FfiConverterOptionalTypeHolderKind implements FfiConverterRustBuffer<HolderKind> {
  INSTANCE;

  @Override
  public HolderKind read(java.nio.ByteBuffer buf) {
    if (buf.get() == (byte)0) {
      return null;
    }
    return FfiConverterTypeHolderKind.INSTANCE.read(buf);
  }

  @Override
  public long allocationSize(HolderKind value) {
    if (value == null) {
      return 1L;
    } else {
      return 1L + FfiConverterTypeHolderKind.INSTANCE.allocationSize(value);
    }
  }

  @Override
  public void write(HolderKind value, java.nio.ByteBuffer buf) {
    if (value == null) {
      buf.put((byte)0);
    } else {
      buf.put((byte)1);
      FfiConverterTypeHolderKind.INSTANCE.write(value, buf);
    }
  }
}



