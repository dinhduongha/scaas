package uniffi.scaas_sdk;


public enum FfiConverterTypeZetherKeyInfo implements FfiConverterRustBuffer<ZetherKeyInfo> {
  INSTANCE;

  @Override
  public ZetherKeyInfo read(java.nio.ByteBuffer buf) {
    return new ZetherKeyInfo(
      FfiConverterString.INSTANCE.read(buf),
      FfiConverterString.INSTANCE.read(buf)
    );
  }

  @Override
  public long allocationSize(ZetherKeyInfo value) {
      return (
            FfiConverterString.INSTANCE.allocationSize(value.ua()) +
            FfiConverterString.INSTANCE.allocationSize(value.y())
      );
  }

  @Override
  public void write(ZetherKeyInfo value, java.nio.ByteBuffer buf) {
      FfiConverterString.INSTANCE.write(value.ua(), buf);
      FfiConverterString.INSTANCE.write(value.y(), buf);
  }
}



