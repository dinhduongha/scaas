package uniffi.scaas_sdk;

public enum FfiConverterOptionalTypeAllowOpaqueCall implements FfiConverterRustBuffer<AllowOpaqueCall> {
  INSTANCE;

  @Override
  public AllowOpaqueCall read(java.nio.ByteBuffer buf) {
    if (buf.get() == (byte)0) {
      return null;
    }
    return FfiConverterTypeAllowOpaqueCall.INSTANCE.read(buf);
  }

  @Override
  public long allocationSize(AllowOpaqueCall value) {
    if (value == null) {
      return 1L;
    } else {
      return 1L + FfiConverterTypeAllowOpaqueCall.INSTANCE.allocationSize(value);
    }
  }

  @Override
  public void write(AllowOpaqueCall value, java.nio.ByteBuffer buf) {
    if (value == null) {
      buf.put((byte)0);
    } else {
      buf.put((byte)1);
      FfiConverterTypeAllowOpaqueCall.INSTANCE.write(value, buf);
    }
  }
}

